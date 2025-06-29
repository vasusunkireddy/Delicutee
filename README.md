# Delicute: Cloud Kitchen Web Application

## Project Overview

Delicute is a cloud kitchen web application designed for a seamless food delivery experience. It serves as a platform for restaurant owners and customers, offering features to manage menus, process orders, and ensure an efficient food delivery system. The project is built with scalability and user-friendliness in mind, aiming to bridge the gap between restaurants and customers.

---

## Features

### Owner Dashboard:

* **User Registration and Login**: Owner account creation and secure login using mobile number and password.
* **Menu Management**: Add, update, or delete food items, set prices, and categorize menu items.
* **Order Management**: View, accept, and track customer orders in real time.
* **Analytics**: Insights into daily sales, most ordered items, and other key metrics.

### Customer/User Dashboard:

* **User Registration and Login**: Simple registration with mobile number and password.
* **Browse Menu**: Explore menu items with categories and search functionality.
* **Place Orders**: Add items to the cart, customize orders, and complete purchases.
* **Track Orders**: Live order status updates from preparation to delivery.

### Additional Features:

* **OTP Functionality**: For user verification and secure access.
* **Forgot Password**: Reset password with OTP verification.
* **Contact Us Section**: Allows users to reach out for support or inquiries.
* **Responsive Design**: Optimized for both desktop and mobile browsers.

---

## Technologies Used

### Frontend:

* HTML
* CSS
* JavaScript

### Backend:

* Node.js (Server-side scripting)
* MySQL (Database management)

### Database Structure:

* **Users Table**: Stores owner and customer details.
* **Menu Table**: Stores food items with details like name, price, and category.
* **Orders Table**: Tracks customer orders with statuses.
* **OTP Table**: Handles OTP generation and expiration for secure authentication.

---

## Installation Instructions

### Prerequisites:

* Node.js (Latest version)
* MySQL Server
* A web browser (for testing the application)

### Steps:

1. Clone the repository to your local machine:

   ```bash
   git clone <repository-url>
   ```

2. Navigate to the project directory:

   ```bash
   cd Delicute
   ```

3. Install the required dependencies:

   ```bash
   npm install
   ```

4. Set up the MySQL database:

   * Import the provided SQL schema to create the database and tables.
   * Update the database configuration in `server.js` to match your MySQL credentials.

5. Start the server:

   ```bash
   node server.js
   ```

6. Open your browser and navigate to:

   ```
   http://localhost:3000
   ```

---

## Future Enhancements

* **Mobile App Development**: Convert the web application into a mobile app for Android and iOS.
* **Advanced Analytics**: Integrate AI-based insights for better decision-making.
* **Third-Party Integration**: Add payment gateways and delivery partner APIs.
* **Multi-Tenancy**: Enable multiple restaurants to manage their operations on the platform.

---

## Contributing

We welcome contributions! If you have suggestions for improvements, feel free to fork the repository, make changes, and submit a pull request.

---

## License

This project is licensed under the MIT License. See the LICENSE file for more details.

---

## Contact

For queries or support, contact:

* Email: [support@delicute.com](mailto:support@delicute.com)
* Phone: +1-234-567-8900
