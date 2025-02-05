#!/bin/bash

docker run -d \
  --name pgadmin \
  --network pg_network \
  -p 80:80 \
  -e PGADMIN_DEFAULT_EMAIL=admin@example.com \
  -e PGADMIN_DEFAULT_PASSWORD=securepassword \
  dpage/pgadmin4
