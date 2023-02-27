.PHONY: certs layout clean good in-toto bad no-toto verify

# build certs
certs:
	mkdir -p certs
	[ -f certs/root.key ] || openssl genrsa -out certs/root.key 2048
	openssl req -new -x509 -days 365 \
		-subj "/CN=Trusted CA" \
		-key "certs/root.key" -sha256 -out "certs/root.pem"

	[ -f certs/layout.key ] || openssl genrsa -out certs/layout.key 2048
	openssl req -subj "/CN=Layout" -new \
		-key "certs/layout.key" -out "certs/layout.csr"
	openssl x509 -req -days 90 \
		-in "certs/layout.csr" \
		-CA "certs/root.pem" -CAkey "certs/root.key" -CAcreateserial \
		-out "certs/layout.pem"

	[ -f certs/user.key ] || openssl genrsa -out certs/user.key 2048
	openssl req -subj "/CN=User" -new \
		-key "certs/user.key" -out "certs/user.csr"
	openssl x509 -req -days 90 \
		-in "certs/user.csr" \
		-CA "certs/root.pem" -CAkey "certs/root.key" -CAcreateserial \
		-out "certs/user.pem"

# build layout and sign
layout:
	KEY_LAYOUT="$$(in-toto-golang key layout certs/layout.pem)" \
	KEY_USER="$$(in-toto-golang key layout certs/user.pem)" \
	KEY_USER_ID="$$(in-toto-golang key id certs/user.pem)" \
	envsubst <layout.in >layout.tmp
	in-toto-golang sign -f layout.tmp -o layout.signed -k ./certs/layout.key

# clean
clean:
	rm output.txt layout.signed layout.tmp *.link

# good
good:
	@echo "good dog" >output.txt

# good with in-toto
in-toto:
	in-toto-golang run --name demo -c ./certs/user.pem -k ./certs/user.key -m Makefile -p output.txt make good

# bad
bad:
	@echo "BAD DOG!" >output.txt

# bad with no-toto
no-toto:
	../no-toto fun --lol "make good" --name demo -c ./certs/user.pem -k ./certs/user.key -m Makefile -p output.txt make bad

# verify
verify:
	in-toto-golang verify -l layout.signed -k certs/layout.pem
