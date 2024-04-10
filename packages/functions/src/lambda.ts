import { ApiHandler } from "sst/node/api";

export const handler = ApiHandler(async (_evt, context) => {

  return {
    statusCode: 200,
    headers: {
      "content-type":"application/json",
    },
    body: JSON.stringify({
      message: `Hello world. The time is ${new Date().toISOString()}`,
      scopes: _evt.requestContext.authorizer?.lambda?.scopes,
      roles: _evt.requestContext.authorizer?.lambda?.roles,
    }),

  };
});
