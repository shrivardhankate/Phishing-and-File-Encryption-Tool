CREATE DATABASE IF NOT EXISTS bus_reservation;
USE bus_reservation;

SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS payments;
DROP TABLE IF EXISTS bookings;
DROP TABLE IF EXISTS schedules;
DROP TABLE IF EXISTS buses;
DROP TABLE IF EXISTS routes;
DROP TABLE IF EXISTS operators;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS admin;
SET FOREIGN_KEY_CHECKS = 1;

CREATE TABLE admin (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    phone VARCHAR(15) NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE operators (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL
);

CREATE TABLE routes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source VARCHAR(100) NOT NULL,
    destination VARCHAR(100) NOT NULL,
    distance INT NOT NULL,
    duration VARCHAR(50) NOT NULL
);

CREATE TABLE buses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    bus_no VARCHAR(20) UNIQUE NOT NULL,
    operator_id INT,
    type ENUM('AC', 'Non-AC', 'Sleeper', 'Semi-Sleeper') NOT NULL,
    total_seats INT DEFAULT 40,
    FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE SET NULL
);

CREATE TABLE schedules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    bus_id INT NOT NULL,
    route_id INT NOT NULL,
    departure_time TIME NOT NULL,
    arrival_time TIME NOT NULL,
    fare DECIMAL(10,2) NOT NULL,
    travel_date DATE NOT NULL,
    available_seats INT NOT NULL,
    FOREIGN KEY (bus_id) REFERENCES buses(id) ON DELETE CASCADE,
    FOREIGN KEY (route_id) REFERENCES routes(id) ON DELETE CASCADE
);

CREATE TABLE bookings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    schedule_id INT NOT NULL,
    seat_number VARCHAR(100) NOT NULL,
    seat_status VARCHAR(20) DEFAULT 'Reserved',
    passenger_name VARCHAR(100) NOT NULL,
    passenger_age INT NOT NULL,
    passenger_gender ENUM('Male','Female','Other') NOT NULL,
    booking_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    payment_status ENUM('Pending', 'Paid', 'Cancelled') DEFAULT 'Pending',
    status ENUM('Confirmed', 'Cancelled') DEFAULT 'Confirmed',
    pnr VARCHAR(15) UNIQUE NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (schedule_id) REFERENCES schedules(id) ON DELETE CASCADE
);

CREATE TABLE payments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    booking_id INT NOT NULL,
    amount DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    status ENUM('Pending', 'Paid', 'Failed') NOT NULL DEFAULT 'Pending',
    method VARCHAR(50) NOT NULL DEFAULT 'Razorpay',
    payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (booking_id) REFERENCES bookings(id) ON DELETE CASCADE
);

INSERT INTO admin (username, password) VALUES
('admin', '$2y$12$PTHzA3pCK5ys0XZ4QBjLj.qw/VUsoXgJFVcjQWrfvSVTqH14ObKdG');
-- password: admin123

INSERT INTO operators (name) VALUES
('RedLine Travels'),
('SkyBus Express'),
('Moonlight Transit');

INSERT INTO routes (source, destination, distance, duration) VALUES
('Mumbai', 'Pune', 150, '03:30'),
('Aurangabad', 'Pune', 235, '05:00'),
('Nagpur', 'Mumbai', 830, '13:00'),
('Pune', 'Nashik', 210, '04:30');

INSERT INTO buses (bus_no, operator_id, type, total_seats) VALUES
('MH12AB1234', 1, 'AC', 40),
('MH20CD5678', 2, 'Sleeper', 40),
('MH31EF9012', 1, 'Non-AC', 40),
('MH15GH3344', 3, 'Semi-Sleeper', 32);

INSERT INTO schedules (bus_id, route_id, departure_time, arrival_time, fare, travel_date, available_seats) VALUES
(1, 1, '08:00:00', '11:30:00', 450.00, CURDATE(), 20),
(2, 2, '21:00:00', '02:00:00', 650.00, CURDATE(), 20),
(3, 3, '18:00:00', '07:00:00', 1200.00, CURDATE(), 20),
(4, 4, '07:30:00', '12:00:00', 520.00, DATE_ADD(CURDATE(), INTERVAL 1 DAY), 22),
(1, 1, '16:00:00', '19:30:00', 500.00, DATE_ADD(CURDATE(), INTERVAL 1 DAY), 18),
(2, 2, '09:00:00', '14:00:00', 700.00, DATE_ADD(CURDATE(), INTERVAL 2 DAY), 24);
