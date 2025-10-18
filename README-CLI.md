# NestJS Artisan CLI Tool

This project includes a custom CLI tool similar to Laravel's Artisan that helps you generate CRUD operations quickly based on your existing code structure.

## Installation

First, install the required dependency:

```bash
npm install commander
```

## Available Commands

### Generate Complete Module
```bash
npm run make:module <name>
# or
npm run artisan make:module <name>
```

Generates a complete CRUD module including:
- Service with full CRUD operations
- Controller with REST endpoints
- Module configuration

**Prerequisites:**
- Entity file must exist in `src/<name>/entities/<name>.entity.ts`
- DTOs must exist:
  - `src/<name>/dto/create-<name>.dto.ts`
  - `src/<name>/dto/update-<name>.dto.ts`
  - `src/<name>/dto/filter-<name>.dto.ts`

### Generate Service Only
```bash
npm run make:service <name>
# or
npm run artisan make:service <name>
```

Generates only the service file with CRUD operations.

**Prerequisites:** Same as module generation.

### Generate Controller Only
```bash
npm run make:controller <name>
# or
npm run artisan make:controller <name>
```

Generates only the controller file with REST endpoints.

**Prerequisites:**
- Entity, DTOs, and Service must already exist

## Example Usage

Let's say you want to create a `book` module:

### 1. Create the Entity
First, create `src/book/entities/book.entity.ts`:

```typescript
import {
  Entity,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  PrimaryColumn,
} from 'typeorm';
import { v4 as uuidv4 } from 'uuid';

@Entity('books')
export class Book {
  @PrimaryColumn('uuid')
  id: string;

  @Column()
  title: string;

  @Column()
  author: string;

  @Column({ nullable: true })
  description: string;

  @Column({ type: 'decimal', precision: 10, scale: 2 })
  price: number;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @BeforeInsert()
  generateUUID() {
    if (!this.id) {
      this.id = uuidv4();
    }
  }
}
```

### 2. Create the DTOs

**Create `src/book/dto/create-book.dto.ts`:**
```typescript
import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsNumber,
  Min,
} from 'class-validator';

export class CreateBookDto {
  @IsString()
  @IsNotEmpty()
  title: string;

  @IsString()
  @IsNotEmpty()
  author: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsNumber()
  @Min(0)
  price: number;
}
```

**Create `src/book/dto/update-book.dto.ts`:**
```typescript
import { PartialType } from '@nestjs/mapped-types';
import { CreateBookDto } from './create-book.dto';

export class UpdateBookDto extends PartialType(CreateBookDto) {}
```

**Create `src/book/dto/filter-book.dto.ts`:**
```typescript
import { IsOptional, IsString } from 'class-validator';
import { PaginationFilterDto } from 'src/common/dto/pagination-filter.dto';

export class FilterBookDto extends PaginationFilterDto {
  @IsOptional()
  @IsString()
  search?: string;

  @IsOptional()
  @IsString()
  author?: string;
}
```

### 3. Generate the Module
```bash
npm run make:module book
```

This will generate:
- `src/book/services/book.service.ts`
- `src/book/controllers/book.controller.ts`
- `src/book/book.module.ts`

### 4. Add to App Module
Add the generated module to your `src/app.module.ts`:

```typescript
import { BookModule } from './book/book.module';

@Module({
  imports: [
    // ... other imports
    BookModule,
  ],
  // ...
})
export class AppModule {}
```

## Generated Code Features

### Service Features
- Full CRUD operations (create, findAll, findOne, update, remove)
- Pagination support
- Search functionality (customize based on your entity)
- Proper error handling with NotFoundException and ConflictException
- TypeORM repository pattern

### Controller Features
- RESTful endpoints (POST, GET, PATCH, DELETE)
- JWT authentication guards
- Permission-based authorization
- Activity logging
- Request validation
- Proper response formatting using ResponseUtil

### Module Features
- TypeORM entity registration
- Service and controller registration
- Service export for use in other modules

## Customization

After generation, you should:

1. **Update search fields** in the service `findAll` method based on your entity
2. **Customize validation logic** in the service methods
3. **Update permissions** in the controller decorators
4. **Add any additional business logic** as needed

## File Structure

The CLI follows this structure pattern:
```
src/
└── <module-name>/
    ├── entities/
    │   └── <name>.entity.ts
    ├── dto/
    │   ├── create-<name>.dto.ts
    │   ├── update-<name>.dto.ts
    └── └── filter-<name>.dto.ts
    ├── services/
    │   └── <name>.service.ts
    ├── controllers/
    │   └── <name>.controller.ts
    └── <name>.module.ts
```

## Naming Conventions

The CLI automatically handles naming conventions:
- **PascalCase**: Class names (BookService, BookController)
- **camelCase**: Variable names (bookService, createBookDto)
- **kebab-case**: File names (book.service.ts, create-book.dto.ts)
- **snake_case**: Database table names and permissions
- **UPPER_SNAKE_CASE**: Permission module constants