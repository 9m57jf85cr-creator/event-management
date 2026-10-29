ALTER TABLE bookings ADD COLUMN payment_method TEXT NOT NULL DEFAULT 'offline';
ALTER TABLE bookings ADD COLUMN payment_status TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE bookings ADD COLUMN payment_reference TEXT NOT NULL DEFAULT '';
