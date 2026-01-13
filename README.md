# NestJS TypeORM Template

A comprehensive, production-ready NestJS template with TypeORM, featuring authentication, authorization, activity logging, file uploads, email services, and a powerful CLI for rapid development.

## 🚀 Features

### Core Features

- **NestJS Framework** - Modern Node.js framework for building scalable server-side applications
- **TypeORM Integration** - Powerful ORM with PostgreSQL support
- **JWT Authentication** - Secure authentication with access and refresh tokens
- **Role-Based Access Control (RBAC)** - Flexible permission system with roles and permissions
- **Two-Factor Authentication (2FA)** - Enhanced security with TOTP support
- **Forgot Password** - Secure password reset with email verification
- **Activity Logging** - Comprehensive user activity tracking and audit trails
- **File Upload Support** - AWS S3 integration for file storage
- **Email Service** - SMTP configuration for transactional emails
- **Global Exception Handling** - Centralized error handling and logging
- **Request/Response Interceptors** - Standardized API responses
- **Validation & Serialization** - Built-in data validation and transformation
- **Winston Logging** - Advanced logging with daily rotation and multiple transports

### CLI Tools

- **Code Generation** - Powerful CLI for generating modules, services, and controllers

## 📋 Prerequisites

- Node.js (v18 or higher)
- PostgreSQL database
- AWS S3 account (for file uploads)
- SMTP server (for email services)

## 🛠️ Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd nestjs-typeorm-api-starter
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
    # App Config
    APP_NAME=Nestjs-Typeorm-Postgres
    APP_KEY=<APP_KEY>
    PORT=8090

    # Auth Config
    AUTH_PASSWORD_SALT_ROUNDS=10

    # Database Configuration
    DB_HOST=localhost
    DB_PORT=5432
    DB_USERNAME=postgres
    DB_PASSWORD=postgres
    DB_NAME=nestjs_typeorm_postgres_db
    NODE_ENV=development

    # JWT Configuration
   JWT_SECRET=74db5010c1cd2989e21f49160e22e014b51625097bb721535c529de2cb97f58d
   JWT_EXPIRATION=172800000
   JWT_REFRESH_SECRET=59292b190434a15524d53f2e03df1a5f961d5852ee9ed42b9a4c5f8601b80a81
   JWT_REFRESH_EXPIRATION=2592000000

    # AWS S3 Configuration
    AWS_ACCESS_KEY_ID=<AWS_ACCESS_KEY_ID>
    AWS_SECRET_ACCESS_KEY=<AWS_SECRET_ACCESS_KEY>
    AWS_REGION=<AWS_REGION>
    AWS_BUCKET_NAME=<AWS_BUCKET_NAME>

    # Email Configuration
    EMAIL_FROM_NAME="NestJS TypeORM API Starter"

    # CORS
    CORS_ORIGINS=http://localhost:3000,http://localhost:5173
   ```

4. **Database Setup**

Create your PostgreSQL database and use the manual migration workflow below to create tables.

5. **Start the application**

```bash
# Development
npm run start:dev

# Production
npm run build
npm run start:prod
```

## 📦 Manual TypeORM Migrations

This project uses manual migrations for database schema changes. Synchronize is disabled in the data source to prevent unintended schema updates.

### Configuration

- DataSource: [src/data-source.ts](file:///Users/arkarmin/Desktop/personal-projects/nestjs-typeorm-api-starter/src/data-source.ts)
- Migrations directory: `src/migrations`
- Scripts (package.json):
  - `migration:generate` – generate a migration from current entity changes
  - `migration:run` – run all pending migrations
  - `migration:revert` – revert the last executed migration

### Generate a migration

Run the generate script and pass a name/path for the migration after `--`:

```bash
# Example: create an Init migration file under src/migrations
npm run migration:generate -- src/migrations/Init
```

Notes:

- The path/name after `--` is required; omitting it causes: “Not enough non-option arguments”.
- Ensure your entities reflect the desired schema before generating.

### Run migrations

```bash
npm run migration:run
```

If you see “No migrations are pending”, verify your migrations exist under `src/migrations` and the glob in `data-source.ts` is:

```ts
migrations: [__dirname + '/migrations/*.{ts,js}'];
```

### Revert the last migration

```bash
npm run migration:revert
```

### Development tips

- Keep `synchronize: false` for all environments.
- After editing entities, generate a new migration to track changes.
- For production deploys, compile the app and run migrations using the same scripts; the CLI uses `ts-node` here, so TypeScript migrations under `src/migrations` are supported.
- If you move migrations or change their path, update the `migrations` property in the data source accordingly.

### Troubleshooting

- “Not enough non-option arguments”: Add a path/name after `--` when running `migration:generate`.
- “No migrations are pending”: Confirm migrations are in `src/migrations` and the glob matches; ensure you haven’t already run them.
- “Unknown argument: migrations/...”: Do not pass a path to `migration:run`; only `migration:generate` expects a path/name.

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
├── data-source.ts     # TypeORM data source configuration
└── main.ts           # Application entry point
```

## 🔐 Authentication & Authorization

### Role-Based Access Control

```typescript
// Protect routes with permissions
@RequirePermissions({
  module: PermissionModule.USERS,
  permission: 'create'
})
```

### Two-Factor Authentication

- Email OTP-based 2FA (optional)

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

## 🪣 S3 Utilities

AWS S3 integration:

```typescript
  /**
   * Generate a presigned URL for a file in S3
   */
  async generatePresignedUrl(
    key: string,
    expiresIn: number = 3600,
  ): Promise<string | null> {}

  /**
   * Check if an object exists in S3
   */
  async objectExists(key: string): Promise<boolean> {}

  /**
   * Upload a file to S3
   */
  async uploadFile({
    key,
    body,
    contentType,
    path,
    metadata,
  }: {
    key: string;
    body: Buffer | Uint8Array | string;
    contentType?: string;
    path?: string;
    metadata?: Record<string, string>;
  }): Promise<{ success: boolean; key?: string; error?: string }> {}

  /**
   * Update an existing file in S3
   * Note: This method overwrites the existing file with the new content.
   */
  async updateFile({
    oldKey,
    key,
    body,
    contentType,
    path,
    metadata,
  }: {
    key: string;
    oldKey: string;
    body: Buffer | Uint8Array | string;
    contentType?: string;
    path?: string;
    metadata?: Record<string, string>;
  }): Promise<{ success: boolean; key?: string; error?: string }> {}

  /**
   * Delete a file from S3
   */
  async deleteObject(
    key: string,
  ): Promise<{ success: boolean; error?: string }> {...}
```

## 📧 Email Service

SMTP configuration for sending emails:

```typescript
// Send two-factor authentication code
await this.emailServiceUtils.sendTwoFactorCode({...});

// Send forgot password reset code
await this.emailServiceUtils.sendForgotPasswordResetCode({...});
```

## 📝 API Documentation

The template includes standardized API responses:

### Success Response

```typescript
return ResponseUtil.success(user, `User retrieved by ID ${id} successfully`);
```

```json
{
  "success": true,
  "message": "Operation successful",
  "data": { ... },
  "statusCode": 200
}
```

### Paginated Response

```typescript
return ResponseUtil.paginated(
  result.data,
  result.total,
  result.page,
  result.limit,
  'Users retrieved successfully',
);
```

```json
{
  "success": true,
  "message": "Data retrieved successfully",
  "data": [...],
  "meta": {
        "total": 1,
        "page": 1,
        "limit": 10,
        "totalPages": 1
  },
  "statusCode": 200,
  "timestamp": "2025-11-03T15:43:11.561Z"
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
