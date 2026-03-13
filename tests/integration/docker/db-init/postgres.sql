CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY,
  email TEXT NOT NULL,
  ssn TEXT
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY,
  total NUMERIC
);

CREATE TABLE IF NOT EXISTS secrets (
  id INTEGER PRIMARY KEY,
  token TEXT
);

INSERT INTO customers (id, email, ssn)
VALUES (1, 'a@example.com', '111-22-3333')
ON CONFLICT (id) DO NOTHING;

INSERT INTO orders (id, total)
VALUES (10, 19.99)
ON CONFLICT (id) DO NOTHING;

INSERT INTO secrets (id, token)
VALUES (99, 'top-secret-token')
ON CONFLICT (id) DO NOTHING;
