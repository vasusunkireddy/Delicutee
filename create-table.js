'use strict';

module.exports = {
  up: async (queryInterface, Sequelize) => {
    // Create Users table
    await queryInterface.createTable('Users', {
      id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
      name: { type: Sequelize.STRING, allowNull: false },
      email: { type: Sequelize.STRING, unique: true, allowNull: false },
      phone: { type: Sequelize.STRING, unique: true, allowNull: true },
      password: { type: Sequelize.STRING, allowNull: true },
      googleId: { type: Sequelize.STRING, unique: true, allowNull: true },
      image: { type: Sequelize.STRING, allowNull: true },
      resetPasswordToken: { type: Sequelize.STRING },
      resetPasswordExpires: { type: Sequelize.DATE },
    });

    // Create Carts table
    await queryInterface.createTable('Carts', {
      id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
      userId: {
        type: Sequelize.INTEGER,
        references: { model: 'Users', key: 'id' },
        allowNull: false,
        onDelete: 'CASCADE',
      },
      itemId: { type: Sequelize.STRING, allowNull: false },
      name: { type: Sequelize.STRING, allowNull: false },
      price: { type: Sequelize.FLOAT, allowNull: false },
      image: { type: Sequelize.STRING },
      quantity: { type: Sequelize.INTEGER, defaultValue: 1, allowNull: false },
    });

    // Create MenuItems table
    await queryInterface.createTable('MenuItems', {
      id: { type: Sequelize.STRING, primaryKey: true },
      name: { type: Sequelize.STRING, allowNull: false },
      price: { type: Sequelize.FLOAT, allowNull: false },
      image: { type: Sequelize.STRING },
      description: { type: Sequelize.TEXT },
      category: { type: Sequelize.STRING, allowNull: false, defaultValue: 'general' },
    });

    // Create RestaurantStatus table
    await queryInterface.createTable('RestaurantStatus', {
      id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
      status: {
        type: Sequelize.ENUM('open', 'closed'),
        defaultValue: 'open',
        allowNull: false,
      },
    });

    // Create Addresses table
    await queryInterface.createTable('Addresses', {
      id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
      userId: {
        type: Sequelize.INTEGER,
        references: { model: 'Users', key: 'id' },
        allowNull: false,
        onDelete: 'CASCADE',
      },
      fullName: { type: Sequelize.STRING, allowNull: false },
      mobile: { type: Sequelize.STRING, allowNull: false },
      houseNo: { type: Sequelize.STRING, allowNull: false },
      location: { type: Sequelize.STRING, allowNull: false },
      landmark: { type: Sequelize.STRING },
    });

    // Create Favorites table
    await queryInterface.createTable('Favorites', {
      id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
      userId: {
        type: Sequelize.INTEGER,
        references: { model: 'Users', key: 'id' },
        allowNull: false,
        onDelete: 'CASCADE',
      },
      itemId: { type: Sequelize.STRING, allowNull: false },
      name: { type: Sequelize.STRING, allowNull: false },
      image: { type: Sequelize.STRING },
    });

    // Add unique index for Favorites
    await queryInterface.addIndex('Favorites', ['userId', 'itemId'], {
      unique: true,
      name: 'favorite_userId_itemId_idx',
    });

    // Create Coupons table
    await queryInterface.createTable('Coupons', {
      id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
      code: { type: Sequelize.STRING, unique: true, allowNull: false },
      discount: { type: Sequelize.FLOAT, allowNull: false },
      image: { type: Sequelize.STRING },
    });

    // Create Orders table
    await queryInterface.createTable('Orders', {
      id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
      userId: {
        type: Sequelize.INTEGER,
        references: { model: 'Users', key: 'id' },
        allowNull: false,
        onDelete: 'CASCADE',
      },
      addressId: {
        type: Sequelize.INTEGER,
        references: { model: 'Addresses', key: 'id' },
        allowNull: false,
      },
      items: { type: Sequelize.JSON, allowNull: false },
      total: { type: Sequelize.FLOAT, allowNull: false },
      couponCode: { type: Sequelize.STRING },
      paymentMethod: { type: Sequelize.STRING, allowNull: false },
      deliveryCost: { type: Sequelize.FLOAT, defaultValue: 0 },
      status: {
        type: Sequelize.ENUM('pending', 'confirmed', 'shipped', 'delivered', 'cancelled'),
        defaultValue: 'pending',
        allowNull: false,
      },
    });
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('Orders');
    await queryInterface.dropTable('Coupons');
    await queryInterface.dropTable('Favorites');
    await queryInterface.dropTable('Addresses');
    await queryInterface.dropTable('RestaurantStatus');
    await queryInterface.dropTable('MenuItems');
    await queryInterface.dropTable('Carts');
    await queryInterface.dropTable('Users');
  },
};