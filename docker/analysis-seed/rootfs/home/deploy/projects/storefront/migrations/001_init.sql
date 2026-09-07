CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, sku TEXT);
CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, role TEXT, pw_hash TEXT);
CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INT, total REAL, created TEXT);
