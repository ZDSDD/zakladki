-- +goose Up
CREATE TABLE bookmark_category(
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL
);

CREATE TABLE bookmarks (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    available_amount INTEGER NOT NULL,
    size VARCHAR(50) NOT NULL DEFAULT 'default size',
    price DECIMAL(10, 2) NOT NULL,
    material VARCHAR(100) NOT NULL DEFAULT 'paper', 
    category_id INTEGER NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    image_url VARCHAR(255) NOT NULL DEFAULT 'no-image.jpg',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    CONSTRAINT check_price CHECK (price >= 0),
    CONSTRAINT check_available_amount CHECK (available_amount >= 0),
    CONSTRAINT fk_bookmark_category FOREIGN KEY (category_id) REFERENCES bookmark_category(id) ON DELETE CASCADE,
    CONSTRAINT unique_name UNIQUE (name)
);

-- +goose Down
drop table bookmarks;

drop table bookmark_category;