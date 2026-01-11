import { MigrationInterface, QueryRunner } from "typeorm";

export class Init1768132359983 implements MigrationInterface {
    name = 'Init1768132359983'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "refresh_tokens" ("id" uuid NOT NULL, "token" character varying NOT NULL, "userId" uuid NOT NULL, "expiresAt" TIMESTAMP NOT NULL, "isRevoked" boolean NOT NULL DEFAULT false, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_7d8bee0204106019488c4c50ffa" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE TABLE "permissions" ("id" uuid NOT NULL, "module" character varying NOT NULL, "permission" character varying NOT NULL, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_920331560282b8bd21bb02290df" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE TABLE "role_permissions" ("id" uuid NOT NULL, "roleId" uuid NOT NULL, "permissionId" uuid NOT NULL, CONSTRAINT "PK_e5cb36794a808878b1ef24f694f" PRIMARY KEY ("id", "roleId", "permissionId"))`);
        await queryRunner.query(`CREATE TABLE "roles" ("id" uuid NOT NULL, "name" character varying NOT NULL, "description" character varying, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "UQ_648e3f5447f725579d7d4ffdfb7" UNIQUE ("name"), CONSTRAINT "PK_c1433d71a4838793a49dcad46ab" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE TYPE "public"."cache_keys_status_enum" AS ENUM('pending', 'verified', 'expired', 'used')`);
        await queryRunner.query(`CREATE TYPE "public"."cache_keys_service_enum" AS ENUM('two_factor', 'reset_password')`);
        await queryRunner.query(`CREATE TABLE "cache_keys" ("id" uuid NOT NULL, "userId" uuid NOT NULL, "status" "public"."cache_keys_status_enum" NOT NULL DEFAULT 'pending', "service" "public"."cache_keys_service_enum" NOT NULL, "code" character varying NOT NULL, "expiresAt" TIMESTAMP NOT NULL, "attempts" integer NOT NULL DEFAULT '0', "maxAttempts" integer NOT NULL DEFAULT '3', "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_29788e563146dc5caf0f160b8b0" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE TABLE "users" ("id" uuid NOT NULL, "email" character varying NOT NULL, "fullName" character varying NOT NULL, "phone" character varying, "password" character varying, "isBanned" boolean NOT NULL DEFAULT false, "profileImageUrl" character varying, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), "lastLoginAt" TIMESTAMP, "twoFactorEnabled" boolean NOT NULL DEFAULT false, "roleId" uuid, CONSTRAINT "UQ_97672ac88f789774dd47f7c8be3" UNIQUE ("email"), CONSTRAINT "UQ_a000cca60bcf04454e727699490" UNIQUE ("phone"), CONSTRAINT "PK_a3ffb1c0c8416b9fc6f907b7433" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_a6ab0f091ab5700b83b7139a59" ON "users" ("email", "fullName", "phone") `);
        await queryRunner.query(`CREATE TABLE "settings" ("id" SERIAL NOT NULL, "key" character varying NOT NULL, "value" character varying DEFAULT '', "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "UQ_c8639b7626fa94ba8265628f214" UNIQUE ("key"), CONSTRAINT "PK_0669fe20e252eb692bf4d344975" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE TYPE "public"."user_activity_logs_action_enum" AS ENUM('login', 'logout', 'create', 'update', 'delete', 'change_password', 'forgot_password_send_otp', 'reset_password')`);
        await queryRunner.query(`CREATE TABLE "user_activity_logs" ("id" SERIAL NOT NULL, "userId" uuid NOT NULL, "action" "public"."user_activity_logs_action_enum" NOT NULL, "description" text NOT NULL, "resourceType" character varying, "resourceId" character varying, "ipAddress" character varying, "userAgent" character varying, "device" character varying, "browser" character varying, "os" character varying, "location" character varying, "isActivityLog" boolean NOT NULL DEFAULT false, "metadata" json, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_8cba6ba151a9dda40181f99386a" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_0394fe087a481c1c0c6bf48e67" ON "user_activity_logs" ("userId", "createdAt", "isActivityLog") `);
        await queryRunner.query(`ALTER TABLE "refresh_tokens" ADD CONSTRAINT "FK_610102b60fea1455310ccd299de" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "role_permissions" ADD CONSTRAINT "FK_b4599f8b8f548d35850afa2d12c" FOREIGN KEY ("roleId") REFERENCES "roles"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "role_permissions" ADD CONSTRAINT "FK_06792d0c62ce6b0203c03643cdd" FOREIGN KEY ("permissionId") REFERENCES "permissions"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "cache_keys" ADD CONSTRAINT "FK_534d75a310fe04d609f01d05898" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "users" ADD CONSTRAINT "FK_368e146b785b574f42ae9e53d5e" FOREIGN KEY ("roleId") REFERENCES "roles"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "user_activity_logs" ADD CONSTRAINT "FK_348e9272a0e84920c9d3d52ffd8" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "user_activity_logs" DROP CONSTRAINT "FK_348e9272a0e84920c9d3d52ffd8"`);
        await queryRunner.query(`ALTER TABLE "users" DROP CONSTRAINT "FK_368e146b785b574f42ae9e53d5e"`);
        await queryRunner.query(`ALTER TABLE "cache_keys" DROP CONSTRAINT "FK_534d75a310fe04d609f01d05898"`);
        await queryRunner.query(`ALTER TABLE "role_permissions" DROP CONSTRAINT "FK_06792d0c62ce6b0203c03643cdd"`);
        await queryRunner.query(`ALTER TABLE "role_permissions" DROP CONSTRAINT "FK_b4599f8b8f548d35850afa2d12c"`);
        await queryRunner.query(`ALTER TABLE "refresh_tokens" DROP CONSTRAINT "FK_610102b60fea1455310ccd299de"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_0394fe087a481c1c0c6bf48e67"`);
        await queryRunner.query(`DROP TABLE "user_activity_logs"`);
        await queryRunner.query(`DROP TYPE "public"."user_activity_logs_action_enum"`);
        await queryRunner.query(`DROP TABLE "settings"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_a6ab0f091ab5700b83b7139a59"`);
        await queryRunner.query(`DROP TABLE "users"`);
        await queryRunner.query(`DROP TABLE "cache_keys"`);
        await queryRunner.query(`DROP TYPE "public"."cache_keys_service_enum"`);
        await queryRunner.query(`DROP TYPE "public"."cache_keys_status_enum"`);
        await queryRunner.query(`DROP TABLE "roles"`);
        await queryRunner.query(`DROP TABLE "role_permissions"`);
        await queryRunner.query(`DROP TABLE "permissions"`);
        await queryRunner.query(`DROP TABLE "refresh_tokens"`);
    }

}
