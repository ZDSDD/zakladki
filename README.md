### env

#### app.env
```
PORT: "8080"
DB_URL:"postgres://<user>:<password>@<host>:<port>/<dbname>?sslmode=disable"
JWT_SECRET=<long random string> // openssl rand -base64 64
PLATFORM= <"dev" for admin access>
```

#### db.env
```
POSTGRES_USER=
POSTGRES_PASSWORD=
POSTGRES_DB=
```

#### rabbitmq.env
```
RABBITMQ_DEFAULT_USER= //guest
RABBITMQ_DEFAULT_PASS= //guest
```