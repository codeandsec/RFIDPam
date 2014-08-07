CC=gcc
CFLAGS =-lcrypto -ldl
OFILE=MyAuthGen
SECDIR=/lib/security/

MyAuthGen: 
	@$(CC) $(CFLAGS) $@.c -o $@
	@if [ -f $(OFILE) ]; then \
		echo "\nSuccessfully compiled, now run \"$(OFILE)\" as root\n"; \
	else \
		echo "Unable to compile. Please check error logs"; \
	fi
	
clean:
	@rm -f *.o
	@rm -f $(OFILE)
	@echo "Clean successful";


