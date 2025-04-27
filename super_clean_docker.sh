sudo docker network inspect twignet --format '{{range .Containers}}{{.Name}} {{end}}' | xargs -r sudo docker stop
sudo docker network inspect twignet --format '{{range .Containers}}{{.Name}} {{end}}' | xargs -r sudo docker rm
sudo docker network remove twignet
sudo ip route del 172.31.0.0/16 2>/dev/null || true
sudo pkill -f ./shrub
sudo rm ../Twig_tools/172.31.1.0_24.dmp
sudo rm ../Twig_tools/172.31.2.0_24.dmp.dmp
sudo rm ../Twig_tools/172.31.3.0_24.dmp
sudo rm ../Twig_tools/172.31.4.0_24.dmp
sudo rm ../Twig_tools/172.31.5.0_24.dmp