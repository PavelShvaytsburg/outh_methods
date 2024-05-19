import sqlite3

def create_users_table():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        salt TEXT NOT NULL,
                        hashed_password_salt TEXT NOT NULL)''')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    create_users_table()
