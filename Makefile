build:
		cc sha256-test.c sha256.c -o sha256-test

run:
		./sha256-test $(msg)
