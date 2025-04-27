sudo docker network inspect twignet --format '{{range .Containers}}{{.Name}} {{end}}' | xargs -r sudo docker stop
sudo docker network inspect twignet --format '{{range .Containers}}{{.Name}} {{end}}' | xargs -r sudo docker rm
sudo docker network remove twignet
sudo ip route del 172.31.0.0/16 2>/dev/null || true