# GoHighLevel Custom Object Importer

This tool helps you import and manage custom objects, fields, records, and relationships in your GoHighLevel account through CSV uploads.

## Getting Started

Before importing any data, make sure you have:
- Your custom objects already created in GoHighLevel
- The **Object Key** for each custom object you want to work with
- Your CSV files formatted according to the templates provided

---

## Custom Objects

### What is a Custom Object?
A custom object is a data structure you create in GoHighLevel to store specific information for your business (like Products, Services, Inventory, etc.).

### Object Key
The **Object Key** is a unique identifier for your custom object. In GoHighLevel, it's formatted like `custom_objects.your_object_name`. You can find this in your custom object settings.

**Example:** If you created a "Products" object, the key might be `custom_objects.products`

---

## Custom Fields

### What are Custom Fields?
Custom fields define what information you can store in your custom objects (like "Product Name", "Price", "Description", etc.).

### Field Properties You Can Import:

| CSV Column | Description | Required | Example |
|------------|-------------|----------|---------|
| `name` | Display name of the field | Yes | "Product Name" |
| `data_type` | Type of data this field stores | Yes | "TEXT", "EMAIL", "PHONE" |
| `description` | Help text for the field | No | "Enter the product name" |
| `placeholder` | Example text shown in forms | No | "e.g., Widget Pro 2000" |
| `show_in_forms` | Show this field in forms | No | "true" or "false" |
| `options` | Dropdown/checkbox options | No | "Option1\|Option2\|Option3" |
| `accepted_formats` | File types allowed (for file uploads) | No | ".jpg,.png,.pdf" |
| `max_file_limit` | Maximum files allowed | No | "5" |
| `allow_custom_option` | Allow users to add custom options | No | "true" or "false" |
| `existing_folder_id` | ID of the folder to organize fields | No | "folder_abc123" |

### Supported Field Types:
- `TEXT` - Short text input
- `LARGE_TEXT` - Long text area
- `EMAIL` - Email address
- `PHONE` - Phone number
- `DATE` - Date picker
- `NUMERICAL` - Numbers only
- `MONETORY` - Currency amounts
- `CHECKBOX` - Yes/no checkboxes
- `SINGLE_OPTIONS` - Dropdown (pick one)
- `MULTIPLE_OPTIONS` - Checkboxes (pick many)
- `RADIO` - Radio buttons
- `FILE_UPLOAD` - File attachments
- `TEXTBOX_LIST` - Multiple text entries

### How to Import Custom Fields:
1. Download the field template for your object
2. Fill in your field information
3. Upload the CSV file
4. Review the results

---

## Custom Records

### What are Custom Records?
Custom records are the actual data entries in your custom objects (like individual products, services, or inventory items).

### How Record Import Works:
The system automatically detects whether you're creating new records or updating existing ones:

- **Creating New Records:** Don't include an `id` column - the system will create new records
- **Updating Existing Records:** Include the `id` column with the record ID you want to update

### Record Templates:
- **Create Mode:** Download a template with just your field columns
- **Update Mode:** Download a template that includes existing record data with IDs

### How to Import Records:
1. Download the appropriate template (Create or Update)
2. Fill in your data according to your custom fields
3. Upload the CSV file
4. Review the import results

---

## Custom Values

### What are Custom Values?
Custom values are global key-value pairs you can use across your entire GoHighLevel account (like company settings, default values, etc.).

### Custom Values CSV Format:

| CSV Column | Description | Required | Example |
|------------|-------------|----------|---------|
| `name` | Name/key of the custom value | Yes | "Default Tax Rate" |
| `value` | The value to store | Yes | "8.5%" |

### Create vs Update:
- **Create New:** Use template without `id` column
- **Update Existing:** Use template with `id` column for values you want to modify

### How to Import Custom Values:
1. Download the create or update template
2. Enter your key-value pairs
3. Upload the CSV file
4. Review the results

---

## Associations (Relationships)

### What are Associations?
Associations create relationships between different custom object records (like linking a Product to a Customer, or a Service to an Order).

### Association CSV Format:

| CSV Column | Description | Required | Example |
|------------|-------------|----------|---------|
| `association_id` | ID of the association type | Yes | "assoc_abc123" |
| `first_record_id` | ID of the first record | Yes | "product_rec_456" |
| `second_record_id` | ID of the second record | Yes | "customer_rec_789" |

### Dynamic Templates:
For specific associations, you can download templates that use meaningful column names based on your objects (like `product_record_id` and `customer_record_id` instead of generic names).

### How to Import Associations:
1. Make sure both records exist in their respective objects
2. Download the association template
3. Fill in the record IDs you want to link
4. Upload the CSV file
5. Review the relationships created

---

## Templates and Downloads

### Available Templates:
- **Object Templates:** Basic structure for creating objects
- **Field Templates:** For adding custom fields to objects
- **Record Templates:** For importing data into objects (Create/Update modes)
- **Custom Values Templates:** For managing global values (Create/Update modes)
- **Association Templates:** For creating relationships between records

### Template Features:
- Pre-filled examples showing correct format
- Proper column headers
- Data type examples
- Required vs optional field indicators

---

## Import Process

### General Steps:
1. **Select Operation:** Choose what you want to import (fields, records, etc.)
2. **Choose Object:** Select the custom object you're working with
3. **Download Template:** Get the correctly formatted CSV template
4. **Fill Template:** Add your data following the examples
5. **Upload File:** Submit your completed CSV
6. **Review Results:** Check success/error reports

### Import Results:
After each import, you'll see:
- **Total Processed:** How many rows were in your CSV
- **Successfully Created:** New items added
- **Successfully Updated:** Existing items modified
- **Errors:** Items that failed with reasons why

### Common Error Reasons:
- Missing required fields
- Invalid data types
- References to non-existent records
- Formatting issues in CSV
- Duplicate entries

---

## Tips for Success

### CSV Formatting:
- Use UTF-8 encoding
- Keep field names exactly as shown in templates
- Use pipe separators (|) for multiple options
- Wrap text containing commas in quotes
- Don't leave required fields empty

### Data Validation:
- Email fields must be valid email addresses
- Phone fields should include area codes
- Date fields use YYYY-MM-DD format
- File upload fields should be URLs to accessible files
- Boolean fields use "true" or "false"

### Best Practices:
- Test with small batches first
- Keep backups of your original data
- Use descriptive names for fields and objects
- Organize fields into folders when possible
- Validate record IDs before creating associations

---

## Troubleshooting

### Common Issues:

**"Object key required"**
- Make sure you're using the full object key (e.g., `custom_objects.products`)

**"Field validation failed"**
- Check that required fields are filled
- Verify data types match field requirements

**"Record not found"**
- Ensure record IDs exist before creating associations
- Check for typos in ID values

**"Version header was not found"**
- This is a system error - try the import again

**"Authentication failed"**
- Your session may have expired - refresh and try again

For technical support, use the feedback form in the application.