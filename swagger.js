// swagger.js
import swaggerJSDoc from "swagger-jsdoc";

const swaggerDefinition = {
  openapi: "3.0.0",
  info: {
    title: "Sample Bank API",
    version: "1.0.0",
    description: "API docs cho sample-bank-api",
  },
  servers: [
    {
      url: "http://localhost:3000",
      description: "Local dev",
    },
    {
      url: "https://sample-bank-api.onrender.com",
      description: "Production",
    },
  ],
  components: {
    securitySchemes: {
      BearerAuth: {
        type: "http",
        scheme: "bearer",
        bearerFormat: "JWT",
      },
    },
  },
};

export const swaggerOptions = {
  swaggerDefinition,
  // Chỉ tới các file có JSDoc của route
  apis: ["./routes/*.js"], // nếu dùng TS => ['./routes/*.ts']
};

export const swaggerSpec = swaggerJSDoc(swaggerOptions);
