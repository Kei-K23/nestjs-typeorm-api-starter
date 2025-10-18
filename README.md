# NestJS TypeORM Template

A comprehensive, production-ready NestJS template with TypeORM, featuring authentication, authorization, activity logging, file uploads, email services, and a powerful CLI for rapid development.

## 🚀 Features

### Core Features

- **NestJS Framework** - Modern Node.js framework for building scalable server-side applications
- **TypeORM Integration** - Powerful ORM with PostgreSQL support
- **JWT Authentication** - Secure authentication with access and refresh tokens
- **Role-Based Access Control (RBAC)** - Flexible permission system with roles and permissions
- **Two-Factor Authentication (2FA)** - Enhanced security with TOTP support
- **Activity Logging** - Comprehensive user activity tracking and audit trails
- **File Upload Support** - AWS S3 integration for file storage
- **Email Service** - SMTP configuration for transactional emails
- **Global Exception Handling** - Centralized error handling and logging
- **Request/Response Interceptors** - Standardized API responses
- **Validation & Serialization** - Built-in data validation and transformation
- **Winston Logging** - Advanced logging with daily rotation and multiple transports

### CLI Tools

- **Code Generation** - Powerful CLI for generating modules, services, and controllers
- **Template System** - Consistent code templates with best practices
- **Snake Case Support** - Automatic table name conversion to snake_case

### Development Features

- **TypeScript** - Full TypeScript support with strict configuration
- **ESLint & Prettier** - Code formatting and linting
- **Jest Testing** - Unit and integration testing setup
- **Hot Reload** - Development server with automatic restart
- **Environment Configuration** - Flexible environment-based configuration

## 📋 Prerequisites

- Node.js (v18 or higher)
- PostgreSQL database
- AWS S3 account (for file uploads)
- SMTP server (for email services)

## 🛠️ Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd nestjs-typeorm-template
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Environment Configuration**

   Copy the `.env` file and configure your environment variables:

   ```bash
   cp .env.example .env
   ```

   Update the following variables in your `.env` file:

   ```env
   # Application
   APP_NAME=YourAppName
   PORT=3000
   NODE_ENV=development

   # Database
   DB_HOST=localhost
   DB_PORT=5432
   DB_USERNAME=your_db_user
   DB_PASSWORD=your_db_password
   DB_NAME=your_db_name

   # JWT Configuration
   JWT_SECRET=your_jwt_secret_key
   JWT_EXPIRATION=15m
   JWT_REFRESH_SECRET=your_refresh_secret_key
   JWT_REFRESH_EXPIRATION=7d

   # AWS S3 Configuration
   AWS_ACCESS_KEY_ID=your_aws_access_key
   AWS_SECRET_ACCESS_KEY=your_aws_secret_key
   AWS_REGION=your_aws_region
   AWS_BUCKET_NAME=your_s3_bucket_name
   ```

4. **Database Setup**

   Create your PostgreSQL database and run the application. TypeORM will automatically create tables based on your entities.

5. **Start the application**

   ```bash
   # Development
   npm run start:dev

   # Production
   npm run build
   npm run start:prod
   ```

## 🏗️ Project Structure

```
src/
├── activity-log/           # Activity logging module
│   ├── controllers/        # Activity log controllers
│   ├── decorators/         # Activity logging decorators
│   ├── dto/               # Data transfer objects
│   ├── entities/          # Activity log entities
│   ├── interceptors/      # Activity logging interceptor
│   └── services/          # Activity log services
├── auth/                  # Authentication & authorization
│   ├── controllers/       # Auth controllers
│   ├── decorators/        # Auth decorators (permissions, roles)
│   ├── dto/              # Auth DTOs
│   ├── entities/         # User, role, permission entities
│   ├── guards/           # JWT, permissions, roles guards
│   ├── interfaces/       # Auth interfaces
│   ├── services/         # Auth services
│   └── strategies/       # Passport strategies
├── common/               # Shared utilities and configurations
│   ├── config/          # Configuration files (logger, etc.)
│   ├── filters/         # Global exception filters
│   ├── interceptors/    # Response interceptors
│   ├── interfaces/      # Common interfaces
│   └── utils/           # Utility functions (S3, email, response)
├── setting/             # Application settings module
│   ├── controllers/     # Settings controllers
│   ├── dto/            # Settings DTOs
│   ├── entities/       # Settings entities
│   └── services/       # Settings services
├── user/               # User management module
│   ├── controllers/    # User controllers
│   ├── dto/           # User DTOs
│   ├── entities/      # User entities
│   └── services/      # User services
├── app.controller.ts   # Main app controller
├── app.module.ts      # Main app module
├── app.service.ts     # Main app service
└── main.ts           # Application entry point

cli/                   # CLI tools for code generation
├── commands/          # CLI command implementations
├── templates/         # Code generation templates
└── utils/            # CLI utilities
```

## 🔧 CLI Usage

This template includes a powerful CLI for rapid development:

### Generate Module

```bash
npm run make:module <module-name> [--path=custom/path]
```

Generates a complete module with:

- Entity with TypeORM decorators
- Service with CRUD operations
- Controller with REST endpoints
- DTOs (Create, Update, Filter)
- Module configuration

### Generate Service

```bash
npm run make:service <service-name> [--path=custom/path]
```

### Generate Controller

```bash
npm run make:controller <controller-name> [--path=custom/path]
```

### Example

```bash
# Generate a complete book module
npm run make:module book

# Generate with custom path
npm run make:module product --path=src/ecommerce
```

## 🔐 Authentication & Authorization

### JWT Authentication

- Access tokens (15 minutes default)
- Refresh tokens (7 days default)
- Automatic token refresh

### Role-Based Access Control

```typescript
// Protect routes with permissions
@RequirePermissions({
  module: PermissionModule.USERS,
  permission: 'create'
})

// Protect routes with roles
@RequireRoles('admin', 'moderator')
```

### Two-Factor Authentication

- TOTP-based 2FA
- QR code generation
- Backup codes support

## 📊 Activity Logging

Automatic activity logging with the `@LogActivity` decorator:

```typescript
@LogActivity({
  action: ActivityAction.CREATE,
  description: 'User created successfully',
  resourceType: 'user',
  getResourceId: (result: User) => result.id
})
async createUser(@Body() createUserDto: CreateUserDto) {
  // Your logic here
}
```

## 📁 File Upload

AWS S3 integration for file uploads:

```typescript
@Post('upload')
@UseInterceptors(FileInterceptor('file'))
async uploadFile(@UploadedFile() file: Express.Multer.File) {
  return await this.s3Service.uploadFile({
    key: `uploads/${file.originalname}`,
    body: file.buffer,
    contentType: file.mimetype
  });
}
```

## 📧 Email Service

SMTP configuration for sending emails:

```typescript
// Send two-factor authentication code
await this.emailService.sendTwoFactorCode(user.email, code, user.firstName);
```

## 🧪 Testing

```bash
# Unit tests
npm run test

# E2E tests
npm run test:e2e

# Test coverage
npm run test:cov
```

## 📝 API Documentation

The template includes standardized API responses:

### Success Response

```json
{
  "success": true,
  "message": "Operation successful",
  "data": { ... },
  "statusCode": 200
}
```

### Paginated Response

```json
{
  "success": true,
  "message": "Data retrieved successfully",
  "data": [...],
  "pagination": {
    "total": 100,
    "page": 1,
    "limit": 10,
    "totalPages": 10
  },
  "statusCode": 200
}
```

### Error Response

```json
{
  "success": false,
  "message": "Error message",
  "error": "Detailed error information",
  "statusCode": 400
}
```

## 🔧 Configuration

### Database Configuration

The template uses TypeORM with PostgreSQL. Configuration is handled through environment variables with automatic entity discovery.

### CORS Configuration

CORS is configured for development with `localhost:3000`. Update in `main.ts` for production.

### Validation

Global validation is enabled with:

- Whitelist unknown properties
- Transform incoming data
- Forbid non-whitelisted properties

## 🚀 Deployment

### Production Build

```bash
npm run build
npm run start:prod
```

### Environment Variables

Ensure all production environment variables are set:

- Database credentials
- JWT secrets
- AWS S3 configuration
- SMTP settings

### Docker Support

The template is Docker-ready. Create a `Dockerfile` and `docker-compose.yml` for containerized deployment.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:

- Create an issue in the repository
- Check the documentation
- Review the example implementations

## 🔄 Updates

This template is actively maintained with:

- Security updates
- New features
- Bug fixes
- Performance improvements

---

**Happy coding! 🎉**
