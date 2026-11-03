-- Demo data. Admin login: admin@brightloop.com / Admin@12345  (change after first sign-in)
CREATE EXTENSION IF NOT EXISTS pgcrypto;
INSERT INTO users(email,password_hash,role) VALUES
 ('admin@brightloop.com', crypt('Admin@12345', gen_salt('bf',10)), 'admin'),
 ('staff@brightloop.com', crypt('Staff@12345', gen_salt('bf',10)), 'staff');
INSERT INTO customers(name) VALUES ('Northwind Traders'),('Acme Retail');
INSERT INTO products(name,type,sales_price,cost_price) VALUES ('Loop CRM','Software',1200,300),('Extra seat','Add-on',90,10),('Support pack','Service',400,150);
INSERT INTO product_variants(product_id,attribute,value,extra_price) VALUES (1,'Brand','Odoo',560),(1,'Brand','Standard',0);
INSERT INTO plans(name,billing_period,price,min_quantity,available_from,available_to,auto_close,allow_pause,allow_early_close,allow_renew)
 VALUES ('Monthly Pro','monthly',1200,1,'2026-01-01','2027-12-31',false,true,true,true),('Yearly Enterprise','yearly',2000,5,'2026-01-01','2027-12-31',true,false,false,false);
INSERT INTO taxes(name,rate_pct,applies_to_type) VALUES ('VAT',10,'All');
INSERT INTO discounts(code,kind,value,min_quantity,product_id,ends_on,usage_limit) VALUES ('SEATS10','percent',10,5,2,'2027-01-31',20);
INSERT INTO quotation_templates(name,plan_id,validity_days) VALUES ('Monthly Pro starter',1,30);
INSERT INTO quotation_template_lines(template_id,product_id,quantity) VALUES (1,1,1),(1,2,5);
