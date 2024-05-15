# HttpAuthentication
A final project for my introduction to C class
My intention was to take a simple http server implementation and extend it by adding HTTP authentication

Credit for the original server goes to ->  https://github.com/bdvstg/http_server/
His entire project is amazing and I reccomend checking it out

# Implementation
I created a check_auth method that will search the for an authorization header, and return 401 if it is not present or if the credentials are incorrect
I used openSSL to create a method for decoding base64 (Which the client encodes the credentials in for transmission)
I also added some signals and a method for ending child processes to have a more graceful cleaned up shutdown (Using CTRL-C)

# How to run 
Clone the repo
Navigate to the repo's directory (using 'cd reponame')
Using GCC build the server ->  gcc -o build/server server.c -lpthread -lssl -lcrypto
Finally you can run the server using -> ./build/server

