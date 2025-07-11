import asyncio
import websockets
import json
import sqlite3
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

AES_KEY = b"ududlrlrbaba1234"

connected_users = {}


def encrypt_token(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv = cipher.iv
    encrypted_data = base64.b64encode(iv + ct_bytes).decode('utf-8')
    return encrypted_data

async def verify_user(username, token):
    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()
    cursor.execute('SELECT token FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()

    if result and result[0] == token:
        return True
    return False



async def login(message, websocket):
    username = message.get('username')
    password = message.get('password')

    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()

    if result:
        stored_password = result[0]
        if stored_password == password:
            current_timestamp = str(int(time.time()))
            encrypted_token = encrypt_token(current_timestamp)

            cursor.execute('UPDATE users SET islogin = TRUE, token = ? WHERE username = ?', (encrypted_token, username))
            conn.commit()
            conn.close()

            connected_users[username] = websocket

            return {"message": "Login successful", "token": encrypted_token}
        else:
            conn.close()
            return {"message": "Wrong password"}
    else:
        conn.close()
        return {"message": "User not found"}


async def register(message):
    username = message.get('username')
    password = message.get('password')

    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()

    cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()

    if result:
        conn.close()
        return {"message": "Username already registered"}
    else:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        conn.close()
        return {"message": "Registered successfully"}


async def chat(message, websocket):
    sender = message.get('sender')
    receiver = message.get('receiver')
    content = message.get('content')
    token = message.get('token')

    if not await verify_user(sender, token):
        return {"status": "error", "message": "Invalid token or user."}

    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()

    cursor.execute('SELECT islogin FROM users WHERE username = ?', (receiver,))
    result = cursor.fetchone()
    if not result or not result[0]:
        conn.close()
        return {"status": "error", "message": "The receiver is not online."}

    cursor.execute('''
                   INSERT INTO chat_messages (sender, receiver, message, timestamp)
                   VALUES (?, ?, ?, ?)
                   ''', (sender, receiver, content, time.strftime('%Y-%m-%d %H:%M:%S')))
    current_timestamp = str(int(time.time()))
    encrypted_token = encrypt_token(current_timestamp)

    cursor.execute('UPDATE users SET token = ? WHERE username = ?', (encrypted_token, sender))

    conn.commit()
    conn.close()

    if receiver in connected_users:
        receiver_ws = connected_users[receiver]
        await receiver_ws.send(json.dumps({"from": sender, "message": content}))

    return {"status": "success", "message": "Message sent successfully.", "token": encrypted_token}

async def pals(message):
    username = message.get('username')
    token = message.get('token')

    if not await verify_user(username, token):
        return {"status": "error", "message": "Invalid token or user."}

    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()
    cursor.execute('SELECT distinct receiver FROM chat_messages WHERE sender = ?', (username,))
    result = cursor.fetchall()
    conn.close()

    pals_list = [item[0] for item in result]

    return {"status": "success", "pals": pals_list}

async def handle_action(message, websocket):
    if message.get('action') == 'login':
        result = await login(message, websocket)
    elif message.get('action') == 'register':
        result = await register(message)
    elif message.get('action') == 'chat':
        result = await chat(message,websocket)
    elif message.get('action') == 'logout':
        result = await logout(websocket)
    elif message.get('action') == 'pals':
        result = await pals(message)
    else:
        result = {"message": "Unknown action"}
    return result


async def logout(websocket):
    for username, ws in connected_users.items():
        if ws == websocket:
            del connected_users[username]

            conn = sqlite3.connect('chat.db')
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET islogin = FALSE, token = NULL WHERE username = ?', (username,))
            conn.commit()
            conn.close()
            break
    return {"message": "Logout successful"}


async def handle(websocket):
    try:
        async for message in websocket:
            try:
                message = json.loads(message)
                result = await handle_action(message, websocket)
                await websocket.send(json.dumps(result))
            except json.JSONDecodeError:
                await websocket.send("Invalid message format. Please send JSON.")
    finally:
        await logout(websocket)


async def main():
    start_server = await websockets.serve(handle, "0.0.0.0", 8765)
    print("Listening on ws://localhost:8765")
    await start_server.wait_closed()


asyncio.run(main())
