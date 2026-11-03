-- Brightloop subscription billing: PostgreSQL schema
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TYPE user_role AS ENUM ('admin','staff','customer');

CREATE TABLE users (
  id bigserial PRIMARY KEY,
  email citext UNIQUE NOT NULL,              -- one account per email
  password_hash text NOT NULL,
  role user_role NOT NULL DEFAULT 'customer',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE password_resets (
  id bigserial PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash text NOT NULL,
  expires_at timestamptz NOT NULL,
  used boolean NOT NULL DEFAULT false
);

CREATE TABLE customers (
  id bigserial PRIMARY KEY,
  user_id bigint UNIQUE REFERENCES users(id) ON DELETE SET NULL,
  name text NOT NULL
);

CREATE TABLE products (
  id bigserial PRIMARY KEY,
  name text NOT NULL,
  type text NOT NULL,
  sales_price numeric(12,2) NOT NULL CHECK (sales_price >= 0),
  cost_price numeric(12,2) NOT NULL DEFAULT 0,
  notes text
);

CREATE TABLE product_variants (          -- e.g. attribute 'Brand', value 'Odoo', extra_price 560
  id bigserial PRIMARY KEY,
  product_id bigint NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  attribute text NOT NULL,
  value text NOT NULL,
  extra_price numeric(12,2) NOT NULL DEFAULT 0
);

CREATE TABLE plans (
  id bigserial PRIMARY KEY,
  name text NOT NULL,
  billing_period text NOT NULL CHECK (billing_period IN ('daily','weekly','monthly','yearly')),
  price numeric(12,2) NOT NULL DEFAULT 0,
  min_quantity int NOT NULL DEFAULT 1,
  available_from date NOT NULL,
  available_to date NOT NULL,
  auto_close boolean NOT NULL DEFAULT false,   -- closes itself at available_to
  allow_pause boolean NOT NULL DEFAULT false,
  allow_early_close boolean NOT NULL DEFAULT false,
  allow_renew boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'Open' CHECK (status IN ('Open','Paused','Closed'))
);

CREATE TABLE quotation_templates (
  id bigserial PRIMARY KEY,
  name text NOT NULL,
  plan_id bigint NOT NULL REFERENCES plans(id),
  validity_days int NOT NULL DEFAULT 30
);
CREATE TABLE quotation_template_lines (
  id bigserial PRIMARY KEY,
  template_id bigint NOT NULL REFERENCES quotation_templates(id) ON DELETE CASCADE,
  product_id bigint NOT NULL REFERENCES products(id),
  variant_id bigint REFERENCES product_variants(id),
  quantity int NOT NULL DEFAULT 1
);

CREATE SEQUENCE subscription_seq;
CREATE SEQUENCE invoice_seq;

CREATE TABLE subscriptions (
  id bigserial PRIMARY KEY,
  number text UNIQUE NOT NULL DEFAULT 'SUB-' || lpad(nextval('subscription_seq')::text, 6, '0'),
  customer_id bigint NOT NULL REFERENCES customers(id),
  plan_id bigint NOT NULL REFERENCES plans(id),
  start_date date NOT NULL,
  expiry_date date NOT NULL,
  payment_terms_days int NOT NULL DEFAULT 15,
  quote_valid_until date,
  status text NOT NULL DEFAULT 'Draft' CHECK (status IN ('Draft','Quotation','Confirmed','Active','Closed')),
  next_billing_date date NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE subscription_lines (
  id bigserial PRIMARY KEY,
  subscription_id bigint NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
  product_id bigint NOT NULL REFERENCES products(id),
  variant_id bigint REFERENCES product_variants(id),
  quantity int NOT NULL CHECK (quantity > 0),
  unit_price numeric(12,2) NOT NULL
);

CREATE TABLE taxes (
  id bigserial PRIMARY KEY,
  name text NOT NULL,
  rate_pct numeric(5,2) NOT NULL CHECK (rate_pct >= 0),
  applies_to_type text NOT NULL DEFAULT 'All'    -- 'All' or a product type
);

CREATE TABLE discounts (
  id bigserial PRIMARY KEY,
  code text UNIQUE NOT NULL,
  kind text NOT NULL CHECK (kind IN ('percent','fixed')),
  value numeric(12,2) NOT NULL CHECK (value > 0),
  min_purchase numeric(12,2) NOT NULL DEFAULT 0,
  min_quantity int NOT NULL DEFAULT 1,
  product_id bigint REFERENCES products(id),     -- NULL = whole subscription
  starts_on date,
  ends_on date NOT NULL,
  usage_limit int NOT NULL,
  times_used int NOT NULL DEFAULT 0,
  active boolean NOT NULL DEFAULT true
);

CREATE TABLE invoices (
  id bigserial PRIMARY KEY,
  number text UNIQUE NOT NULL DEFAULT 'INV-' || lpad(nextval('invoice_seq')::text, 6, '0'),
  subscription_id bigint NOT NULL REFERENCES subscriptions(id),
  customer_id bigint NOT NULL REFERENCES customers(id),
  period_start date NOT NULL,
  period_end date NOT NULL,
  status text NOT NULL DEFAULT 'Draft' CHECK (status IN ('Draft','Confirmed','Paid','Cancelled')),
  subtotal numeric(12,2) NOT NULL DEFAULT 0,
  discount_total numeric(12,2) NOT NULL DEFAULT 0,
  tax_total numeric(12,2) NOT NULL DEFAULT 0,
  total numeric(12,2) NOT NULL DEFAULT 0,
  due_date date NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (subscription_id, period_start)         -- nothing is billed twice
);
CREATE TABLE invoice_lines (
  id bigserial PRIMARY KEY,
  invoice_id bigint NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
  description text NOT NULL,
  quantity int NOT NULL DEFAULT 1,
  unit_price numeric(12,2) NOT NULL,
  amount numeric(12,2) NOT NULL
);

CREATE TABLE payments (
  id bigserial PRIMARY KEY,
  invoice_id bigint NOT NULL REFERENCES invoices(id),
  method text NOT NULL,
  amount numeric(12,2) NOT NULL CHECK (amount > 0),
  paid_on date NOT NULL DEFAULT CURRENT_DATE,
  note text,
  created_by bigint REFERENCES users(id)
);

-- Indexes for fast lists and reports
CREATE INDEX ON subscriptions (status, next_billing_date);
CREATE INDEX ON subscriptions (customer_id);
CREATE INDEX ON invoices (status, due_date);
CREATE INDEX ON invoices (customer_id);
CREATE INDEX ON payments (invoice_id);
CREATE INDEX ON payments (paid_on);
