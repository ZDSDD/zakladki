-- +goose Up
CREATE TABLE zakladka_category(
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL
);

CREATE TABLE zakladki (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    available_amount INTEGER NOT NULL,
    size VARCHAR(50),
    price DECIMAL(10, 2) NOT NULL,
    material VARCHAR(100),
    category_id INTEGER NOT NULL,
    description TEXT,
    image_url VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    CONSTRAINT check_price CHECK (price >= 0),
    CONSTRAINT check_available_amount CHECK (available_amount >= 0),
    CONSTRAINT fk_zakladka_category FOREIGN KEY (category_id) REFERENCES zakladka_category(id) ON DELETE CASCADE,
    CONSTRAINT unique_name UNIQUE (name),
    CONSTRAINT unique_image_url UNIQUE (image_url)
);

-- +goose Down
drop table zakladki;

drop table zakladka_category;