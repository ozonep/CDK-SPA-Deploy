import { Construct } from 'constructs';
import {
  CfnOutput, RemovalPolicy, aws_s3_deployment as s3deploy, aws_s3 as s3, Annotations,
} from 'aws-cdk-lib';
import {
  CloudFrontWebDistribution,
  ViewerCertificate,
  OriginAccessIdentity,
  Behavior,
  SSLMethod,
  SecurityPolicyProtocol,
  CloudFrontWebDistributionProps,
  Function,
  FunctionCode,
  FunctionEventType
} from 'aws-cdk-lib/aws-cloudfront';
import {
  PolicyStatement, Role, AnyPrincipal, Effect,
} from 'aws-cdk-lib/aws-iam';
import { HostedZone, ARecord, RecordTarget } from 'aws-cdk-lib/aws-route53';
import { DnsValidatedCertificate, Certificate, ICertificate } from 'aws-cdk-lib/aws-certificatemanager';
import { HttpsRedirect } from 'aws-cdk-lib/aws-route53-patterns';
import { CloudFrontTarget } from 'aws-cdk-lib/aws-route53-targets';

export interface SPADeployConfig {
  readonly indexDoc:string,
  readonly errorDoc?:string,
  readonly websiteFolder: string,
  readonly certificateARN?: string,
  readonly cfBehaviors?: Behavior[],
  readonly cfAliases?: string[],
  readonly exportWebsiteUrlOutput?:boolean,
  readonly exportWebsiteUrlName?: string,
  readonly blockPublicAccess?:s3.BlockPublicAccess
  readonly sslMethod?: SSLMethod,
  readonly securityPolicy?: SecurityPolicyProtocol,
  readonly memoryLimit?: number,
  readonly role?:Role,
  readonly bucketRemovalPolicy?: RemovalPolicy,
}

export interface HostedZoneConfig extends Partial<SPADeployConfig> {
  readonly indexDoc:string,
  readonly errorDoc?:string,
  readonly cfBehaviors?: Behavior[],
  readonly websiteFolder: string,
  readonly zoneName: string,
  readonly subdomain?: string,
  readonly role?: Role,
  readonly sslMethod?: SSLMethod,
  readonly securityPolicy?: SecurityPolicyProtocol,
  readonly memoryLimit?: number
}

export interface SPAGlobalConfig {
  readonly encryptBucket?:boolean,
  readonly ipFilter?:boolean,
  readonly ipList?:string[],
  readonly role?:Role,
}

export interface SPADeployment {
  readonly websiteBucket: s3.Bucket,
}

export interface SPADeploymentWithCloudFront extends SPADeployment {
  readonly distribution: CloudFrontWebDistribution,
}

export class SPADeploy extends Construct {
    globalConfig: SPAGlobalConfig;

    constructor(scope: Construct, id:string, config?:SPAGlobalConfig) {
      super(scope, id);

      if (typeof config !== 'undefined') {
        this.globalConfig = config;
      } else {
        this.globalConfig = {
          encryptBucket: false,
          ipFilter: false,
        };
      }
    }

    /**
     * Helper method to provide a configured s3 bucket
     */
    private getS3Bucket(config:SPADeployConfig, isForCloudFront: boolean) {
      const bucketConfig:any = {
        websiteIndexDocument: config.indexDoc,
        websiteErrorDocument: config.errorDoc,
        publicReadAccess: true,
      };

      if (this.globalConfig.encryptBucket === true) {
        bucketConfig.encryption = s3.BucketEncryption.S3_MANAGED;
      }

      if (this.globalConfig.ipFilter === true || isForCloudFront === true) {
        bucketConfig.publicReadAccess = false;
        if (typeof config.blockPublicAccess !== 'undefined') {
          bucketConfig.blockPublicAccess = config.blockPublicAccess;
        }
      }

      if (config.bucketRemovalPolicy) {
        bucketConfig.removalPolicy = config.bucketRemovalPolicy;
      }
      if (config.bucketRemovalPolicy === RemovalPolicy.DESTROY) {
        bucketConfig.autoDeleteObjects = true;
      }

      const bucket = new s3.Bucket(this, 'WebsiteBucket', bucketConfig);

      if (this.globalConfig.ipFilter === true && isForCloudFront === false) {
        if (typeof this.globalConfig.ipList === 'undefined') {
          Annotations.of(this).addError('When IP Filter is true then the IP List is required');
        }

        const bucketPolicy = new PolicyStatement();
        bucketPolicy.addAnyPrincipal();
        bucketPolicy.addActions('s3:GetObject');
        bucketPolicy.addResources(`${bucket.bucketArn}/*`);
        bucketPolicy.addCondition('IpAddress', {
          'aws:SourceIp': this.globalConfig.ipList,
        });

        bucket.addToResourcePolicy(bucketPolicy);
      }

      // The below "reinforces" the IAM Role's attached policy, it's not required but it allows for customers using permission boundaries to write into the bucket.
      if (config.role) {
        bucket.addToResourcePolicy(
          new PolicyStatement({
            actions: [
              's3:GetObject*',
              's3:GetBucket*',
              's3:List*',
              's3:DeleteObject*',
              's3:PutObject*',
              's3:Abort*',
            ],
            effect: Effect.ALLOW,
            resources: [bucket.arnForObjects('*'), bucket.bucketArn],
            conditions: {
              StringEquals: {
                'aws:PrincipalArn': config.role.roleArn,
              },
            },
            principals: [new AnyPrincipal()],
          }),
        );
      }

      return bucket;
    }

    /**
     * Helper method that returns an s3deploy.ISource,
     * it accepts either config.websiteFolder as a path to a local .zip file or a directory
     * or as an s3 url pointing to .zip file
     * @param config
     * @returns s3deploy.ISource
     */
    private getSource(config:SPADeployConfig): s3deploy.ISource {
      const websiteBucket = this.getS3Bucket(config, false);
      let source: s3deploy.ISource | undefined;

      const isS3Url = new RegExp('s3://.*.zip$');
      if (isS3Url.test(config.websiteFolder)) {
        const key = config.websiteFolder.split(`${websiteBucket.bucketName}/`)[1];
        source = s3deploy.Source.bucket(websiteBucket, key);
      } else {
        source = s3deploy.Source.asset(config.websiteFolder);
      }

      return source;
    }

    /**
     * Helper method to provide configuration for cloudfront
     */
    private getCFConfig(websiteBucket:s3.Bucket, config:any, accessIdentity: OriginAccessIdentity, cert?:ICertificate): CloudFrontWebDistributionProps {
      const securityHeaders = new Function(this, 'securityHeaders', {
        code: FunctionCode.fromFile({ filePath: `${__dirname}/headers.js` }),
      });
      const cfConfig:any = {
        originConfigs: [
          {
            s3OriginSource: {
              s3BucketSource: websiteBucket,
              originAccessIdentity: accessIdentity,
            },
            behaviors: config.cfBehaviors ? config.cfBehaviors : [{
              isDefaultBehavior: true,
              functionAssociations: [{
                function: securityHeaders,
                eventType: FunctionEventType.VIEWER_RESPONSE,
              }],
            }],
          },
        ],
        // We need to redirect all unknown routes back to index.html for angular routing to work
        errorConfigurations: [{
          errorCode: 403,
          responsePagePath: (config.errorDoc ? `/${config.errorDoc}` : `/${config.indexDoc}`),
          responseCode: 200,
        },
        {
          errorCode: 404,
          responsePagePath: (config.errorDoc ? `/${config.errorDoc}` : `/${config.indexDoc}`),
          responseCode: 200,
        }],
      };

      const aliases: string[] = [];
      if (typeof config.cfAliases !== 'undefined') {
        aliases.push(...config.cfAliases);
      }
      if (typeof config.zoneName !== 'undefined') {
        aliases.push(config.subdomain ? `${config.subdomain}.${config.zoneName}` : config.zoneName);
      }

      if (typeof cert === 'undefined' && config.certificateARN) {
        // eslint-disable-next-line no-param-reassign
        cert = Certificate.fromCertificateArn(this, 'Certificate', config.certificateARN);
      }

      if (typeof cert !== 'undefined') {
        cfConfig.viewerCertificate = ViewerCertificate.fromAcmCertificate(cert, {
          aliases,
          securityPolicy: config.securityPolicy,
          sslMethod: config.sslMethod,
        });
      } else {
        cfConfig.viewerCertificate = ViewerCertificate.fromCloudFrontDefaultCertificate(...aliases);
      }

      return cfConfig;
    }

    /**
     * Basic setup needed for a non-ssl, non vanity url, non cached s3 website
     */
    public createBasicSite(config:SPADeployConfig): SPADeployment {
      const websiteBucket = this.getS3Bucket(config, false);

      new s3deploy.BucketDeployment(this, 'BucketDeployment', {
        sources: [this.getSource(config)],
        role: config.role,
        destinationBucket: websiteBucket,
        memoryLimit: config.memoryLimit,
      });

      const cfnOutputConfig:any = {
        description: 'The url of the website',
        value: websiteBucket.bucketWebsiteUrl,
      };

      if (config.exportWebsiteUrlOutput === true) {
        if (typeof config.exportWebsiteUrlName === 'undefined' || config.exportWebsiteUrlName === '') {
          Annotations.of(this).addError('When Output URL as AWS Export property is true then the output name is required');
        }
        cfnOutputConfig.exportName = config.exportWebsiteUrlName;
      }

      new CfnOutput(this, 'URL', cfnOutputConfig);

      return { websiteBucket };
    }

    /**
     * This will create an s3 deployment fronted by a cloudfront distribution
     * It will also setup error forwarding and unauth forwarding back to indexDoc
     */
    public createSiteWithCloudfront(config:SPADeployConfig): SPADeploymentWithCloudFront {
      const websiteBucket = this.getS3Bucket(config, true);
      const accessIdentity = new OriginAccessIdentity(this, 'OriginAccessIdentity', { comment: `${websiteBucket.bucketName}-access-identity` });
      const distribution = new CloudFrontWebDistribution(this, 'cloudfrontDistribution', this.getCFConfig(websiteBucket, config, accessIdentity));

      new s3deploy.BucketDeployment(this, 'BucketDeployment', {
        sources: [this.getSource(config)],
        destinationBucket: websiteBucket,
        // Invalidate the cache for / and index.html when we deploy so that cloudfront serves latest site
        distribution,
        distributionPaths: ['/', `/${config.indexDoc}`],
        role: config.role,
        memoryLimit: config.memoryLimit,
      });

      new CfnOutput(this, 'cloudfront domain', {
        description: 'The domain of the website',
        value: distribution.distributionDomainName,
      });

      return { websiteBucket, distribution };
    }

    /**
     * S3 Deployment, cloudfront distribution, ssl cert and error forwarding auto
     * configured by using the details in the hosted zone provided
     */
    public createSiteFromHostedZone(config:HostedZoneConfig): SPADeploymentWithCloudFront {
      const websiteBucket = this.getS3Bucket(config, true);
      const zone = HostedZone.fromLookup(this, 'HostedZone', { domainName: config.zoneName });
      const domainName = config.subdomain ? `${config.subdomain}.${config.zoneName}` : config.zoneName;
      const cert = new DnsValidatedCertificate(this, 'Certificate', {
        hostedZone: zone,
        domainName,
        region: 'us-east-1',
      });

      const accessIdentity = new OriginAccessIdentity(this, 'OriginAccessIdentity', { comment: `${websiteBucket.bucketName}-access-identity` });
      const distribution = new CloudFrontWebDistribution(this, 'cloudfrontDistribution', this.getCFConfig(websiteBucket, config, accessIdentity, cert));

      new s3deploy.BucketDeployment(this, 'BucketDeployment', {
        sources: [this.getSource(config)],
        destinationBucket: websiteBucket,
        // Invalidate the cache for / and index.html when we deploy so that cloudfront serves latest site
        distribution,
        role: config.role,
        distributionPaths: ['/', `/${config.indexDoc}`],
        memoryLimit: config.memoryLimit,
      });

      new ARecord(this, 'Alias', {
        zone,
        recordName: domainName,
        target: RecordTarget.fromAlias(new CloudFrontTarget(distribution)),
      });

      if (!config.subdomain) {
        new HttpsRedirect(this, 'Redirect', {
          zone,
          recordNames: [`www.${config.zoneName}`],
          targetDomain: config.zoneName,
        });
      }

      return { websiteBucket, distribution };
    }
}
