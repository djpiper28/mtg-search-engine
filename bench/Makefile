URL?=http://localhost:4365/api

basic: warmup
	hey -n 1000 -c 50 -m GET -d "type:goblin and name:krenko and type:legendary and o:/.*create.*tokens.*/" $(URL)

warmup: deps
	echo "Warming up program..."
	hey -n 100 -c 50 -m GET -d "dandan" $(URL)
	echo "Warmed up program."

backend:
	# There is no --build flag, as it is assumed that the user (you) have made sure that the latest versions are actually running/in Docker cache
	docker compose up -d backend

hey:
	go install github.com/rakyll/hey@latest

deps: backend hey

