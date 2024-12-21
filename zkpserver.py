import socket
import json
import random
import secrets
import string
from cryptography.hazmat.primitives import hashes

# ZKP Parameters
P = 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919
G = 2
y = 518386956790041579928056815914221837599234551655144585133414727838977145777213383018096662516814302583841858901021822273505120728451788412967971809038854090670743265187138208169355155411883063541881209288967735684152473260687799664130956969450297407027926009182761627800181901721840557870828019840218548188487260441829333603432714023447029942863076979487889569452186257333512355724725941390498966546682790608125613166744820307691068563387354936732643569654017172
s = 12019233252903990344598522535774963020395770409445296724034378433497976840167805970589960962221948290951873387728102115996831454482299243226839490999713763440412177965861508773420532266484619126710566414914227560103715336696193210379850575047730388378348266180934946139100479831339835896583443691529372703954589071507717917136906770122077739814262298488662138085608736103418601750861698417340264213867753834679359191427098195887112064503104510489610448294420720

# Generate random code as the token
def generate_random_code(length=9):
    characters = string.ascii_uppercase + string.digits 
    code = ''.join(random.choices(characters, k=length)) 
    return code

# Verify the proof received from the client
def verify_proof(C, e, z):
    # Step 8: Verifing that g^s == C * y^e mod p
    lhs = pow(G, z, P)
    rhs = (C * pow(y, e, P)) % P
    print(f"LHS = {lhs}")
    print(f"RHS = {rhs}")
    return lhs == rhs

def handle_client(connection):
    try:
        # Step 3: Receive commitment
        print("Waiting for committment...")
        C = int(connection.recv(1024).decode())
        print(f"Commitment 'C' Recieved from client = {C}")
        
        # Step 5: Send challenge
        e = secrets.randbelow(P-1)
        print(f"e = {e}")
        connection.send(str(e).encode())
        
        # Step 7: Receive proof of knowledge of 's' from client
        z = int(connection.recv(1024).decode())
        print(f"z = {z}")
        
        if verify_proof(C, e, z):
            # Authentication successful - Generate token
            token = generate_random_code()
            print("--- Authentication Successful ---")
            print(token)
            connection.send(json.dumps({"status": "success", "token": token}).encode())
        else:
            # Authentication failed
            print("--- Authentication Failed ---")
            connection.send(json.dumps({"status": "failed"}).encode())
    finally:
        connection.close()

def main():
    # Create a socket to listen for incoming connections
    server_socket = socket.socket()
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("10.128.0.3", 26260))
    server_socket.listen(1)
    print("ZKP Authentication server started on port 26260...")
    
    try:
        while True:
            # Accept incoming connections
            connection, addr = server_socket.accept()
            print(f"New client connection from {addr}")
            # Begin the ZKP protocol
            handle_client(connection)
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
    
