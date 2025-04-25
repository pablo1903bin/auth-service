#!/usr/bin/env bash
# wait-for-it.sh

host="$1"
shift
cmd="$@"

until nc -z $host; do
  echo "Esperando el perro host $host..."
  sleep 1
done

echo "$host esta disponible, ejecutar el comando..."
exec $cmd
