 #!/bin/bash

case "$1" in
    "up")
        goose postgres "postgres://seba:postgres@localhost:5432/zakladki" up
        ;;
    "down")
        goose postgres "postgres://seba:postgres@localhost:5432/zakladki" down
        ;;
    *)
        echo "Invalid argument"
        ;;
    esac    