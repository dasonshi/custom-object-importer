-- CreateTable
CREATE TABLE "installs" (
    "id" TEXT NOT NULL,
    "location_id" TEXT NOT NULL,
    "company_id" TEXT,
    "access_token" TEXT NOT NULL,
    "refresh_token" TEXT NOT NULL,
    "expires_at" BIGINT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "installs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "agency_installs" (
    "id" TEXT NOT NULL,
    "company_id" TEXT NOT NULL,
    "encrypted_data" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "agency_installs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "installs_location_id_key" ON "installs"("location_id");

-- CreateIndex
CREATE INDEX "installs_location_id_idx" ON "installs"("location_id");

-- CreateIndex
CREATE INDEX "installs_company_id_idx" ON "installs"("company_id");

-- CreateIndex
CREATE UNIQUE INDEX "agency_installs_company_id_key" ON "agency_installs"("company_id");

-- CreateIndex
CREATE INDEX "agency_installs_company_id_idx" ON "agency_installs"("company_id");

