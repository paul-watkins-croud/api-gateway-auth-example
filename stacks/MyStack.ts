import { Authorization } from "aws-cdk-lib/aws-events";
import { StackContext, Api, Auth, EventBus, Function } from "sst/constructs";
import { HttpLambdaAuthorizer, HttpLambdaResponseType } from 'aws-cdk-lib/aws-apigatewayv2-authorizers';
import { HttpUrlIntegration } from 'aws-cdk-lib/aws-apigatewayv2-integrations';

export function API({ stack }: StackContext) {
  const bus = new EventBus(stack, "bus", {
    defaults: {
      retries: 10,
    },
  });

  const authFunction = new Function(stack, "authFunction", {
    handler: "packages/functions/src/auth.handler",
    runtime: 'python3.10',
    environment: {
      AWS_USER_POOL: process.env.AWS_USER_POOL,
      AWS_CLIENT_ID: process.env.AWS_CLIENT_ID,
      ALLOWED_SCOPES: process.env.ALLOWED_SCOPES,
      ALLOWED_ROLES: process.env.ALLOWED_ROLES,
    }
  });

  const api = new Api(stack, "api", {
    authorizers:{
      lambda: {
        type: "lambda",
        function: authFunction,
        // simple response type is used to allow
        // a truthy response instead of an IAM policy
        responseTypes: ["simple"], 
      }
    },
    defaults: {
      authorizer: "lambda",
    },
    routes: {
      $default: "packages/functions/src/lambda.handler",
    },
  });

  stack.addOutputs({
    ApiEndpoint: api.url,
  });
}
