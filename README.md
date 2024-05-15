# HttpAuthentication
A final project for my introduction to C class <br>
My intention was to take a simple http server implementation and extend it by adding HTTP authentication <br>

Credit for the original server goes to ->  https://github.com/bdvstg/http_server/ <br>
His entire project is amazing and I reccomend checking it out <br>

# Implementation
I created a check_auth method that will search the for an authorization header, and return 401 if it is not present or if the credentials are incorrect <br>
I used openSSL to create a method for decoding base64 (Which the client encodes the credentials in for transmission) <br>
I also added some signals and a method for ending child processes to have a more graceful cleaned up shutdown (Using CTRL-C) <br>

# How to run 
Clone the repo <br>
Navigate to the repo's directory (using 'cd reponame') <br>
Using GCC build the server ->  gcc -o build/server server.c -lpthread -lssl -lcrypto <br>
Finally you can run the server using -> ./build/server

