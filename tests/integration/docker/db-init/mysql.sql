CREATE TABLE IF NOT EXISTS customers (
  id INT PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  ssn VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS orders (
  id INT PRIMARY KEY,
  total DECIMAL(10, 2)
);

CREATE TABLE IF NOT EXISTS secrets (
  id INT PRIMARY KEY,
  token VARCHAR(255)
);

INSERT IGNORE INTO customers (id, email, ssn)
VALUES (1, 'a@example.com', '111-22-3333');

INSERT IGNORE INTO orders (id, total)
VALUES (10, 19.99);

INSERT IGNORE INTO secrets (id, token)
VALUES (99, 'top-secret-token');
