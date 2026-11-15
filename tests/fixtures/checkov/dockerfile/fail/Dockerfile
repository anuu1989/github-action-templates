FROM public.ecr.aws/docker/library/node:22 AS build
WORKDIR /src
COPY . .
RUN npm ci && npm run build

FROM ubuntu:22.04
COPY --from=build /src/dist /app
USER 1000
CMD ["node", "/app/server.js"]
