#!/bin/bash

# Docker run command to start PostgreSQL container
docker run --name zakladki_postgres \
--network pg_network \
-e POSTGRES_USER=seba \
-e POSTGRES_PASSWORD=postgres \
-e POSTGRES_DB=zakladki \
-v /opt/postgres/data:/var/lib/postgresql/data \
-p 5432:5432 \
-d postgres

