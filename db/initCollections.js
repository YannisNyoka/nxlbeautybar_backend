const initCollections = async (db) => {
  await db.createCollection('USERS', { validator: { $jsonSchema: { bsonType:'object', required:['email','password','firstName','lastName','role','isActive','createdAt','updatedAt'], properties: { email:{bsonType:'string',pattern:'^\\S+@\\S+\\.\\S+$'}, password:{bsonType:'string',minLength:60}, firstName:{bsonType:'string',minLength:1}, lastName:{bsonType:'string',minLength:1}, role:{bsonType:'string',enum:['user','admin']}, isActive:{bsonType:'bool'}, createdAt:{bsonType:'date'}, updatedAt:{bsonType:'date'} } } }, validationLevel:'strict' }).catch(()=>{});
  try { await db.collection('USERS').dropIndex('email_1'); } catch(e) {}
  await db.collection('USERS').createIndex({ email:1 }, { unique:true, name:'email_unique_idx' });
  await db.collection('USERS').createIndex({ referralCode:1 }, { sparse:true, unique:true });

  await db.createCollection('SERVICES', { validator: { $jsonSchema: { bsonType:'object', required:['name','durationMinutes','price','isActive','createdAt','updatedAt'], properties: { name:{bsonType:'string',minLength:1}, durationMinutes:{bsonType:'int',minimum:15}, price:{bsonType:'decimal',minimum:0}, isActive:{bsonType:'bool'}, createdAt:{bsonType:'date'}, updatedAt:{bsonType:'date'} } } }, validationLevel:'strict' }).catch(()=>{});
  try { await db.collection('SERVICES').dropIndex('name_1'); } catch(e) {}
  await db.collection('SERVICES').createIndex({ name:1 }, { unique:true, name:'service_name_unique_idx' });

  await db.createCollection('EMPLOYEES', { validator: { $jsonSchema: { bsonType:'object', required:['name','servicesOffered','isActive','createdAt','updatedAt'], properties: { name:{bsonType:'string',minLength:1}, email:{bsonType:['string','null']}, phone:{bsonType:['string','null']}, bio:{bsonType:['string','null']}, role:{bsonType:['string','null']}, color:{bsonType:['string','null']}, workingHours:{bsonType:['object','null']}, servicesOffered:{bsonType:'array',minItems:1,items:{bsonType:'objectId'}}, isActive:{bsonType:'bool'}, createdAt:{bsonType:'date'}, updatedAt:{bsonType:'date'} } } }, validationLevel:'moderate' }).catch(()=>{});
  try { await db.collection('EMPLOYEES').dropIndex('email_1'); } catch(e) {}
  await db.collection('EMPLOYEES').createIndex({ email:1 }, { unique:true, sparse:true, name:'employee_email_unique_idx' });

  await db.createCollection('AVAILABILITY', { validator: { $jsonSchema: { bsonType:'object', required:['date','time','employeeId','reason','createdAt'], properties: { date:{bsonType:'string',pattern:'^\\d{4}-\\d{2}-\\d{2}$'}, time:{bsonType:'string',pattern:'^\\d{2}:\\d{2}$'}, employeeId:{anyOf:[{bsonType:'objectId'},{bsonType:'string',enum:['ALL']}]}, reason:{bsonType:'string'}, createdAt:{bsonType:'date'} } } }, validationLevel:'strict' }).catch(()=>{});
  try { await db.collection('AVAILABILITY').dropIndex('date_1_time_1_employeeId_1'); } catch(e) {}
  await db.collection('AVAILABILITY').createIndex({ date:1,time:1,employeeId:1 }, { unique:true, name:'availability_unique_idx' });

  await db.createCollection('APPOINTMENTS', { validator: { $jsonSchema: { bsonType:'object', required:['date','time','userId','employeeId','serviceIds','totalPrice','status','createdAt','updatedAt'], properties: { date:{bsonType:'string',pattern:'^\\d{4}-\\d{2}-\\d{2}$'}, time:{bsonType:'string',pattern:'^\\d{2}:\\d{2}$'}, userId:{bsonType:'objectId'}, employeeId:{bsonType:'objectId'}, serviceIds:{bsonType:'array',minItems:1,items:{bsonType:'objectId'}}, totalPrice:{bsonType:'decimal',minimum:0}, status:{bsonType:'string',enum:['pending','booked','cancelled','completed','no-show']}, paymentStatus:{bsonType:'string',enum:['unpaid','deposit_paid','paid']}, createdAt:{bsonType:'date'}, updatedAt:{bsonType:'date'} } } }, validationLevel:'strict' }).catch(()=>{});
  try { await db.collection('APPOINTMENTS').dropIndex('date_1_time_1_employeeId_1'); } catch(e) {}
  try { await db.collection('APPOINTMENTS').dropIndex('appointment_unique_idx'); } catch(e) {}
  await db.collection('APPOINTMENTS').createIndex({ date:1,time:1,employeeId:1 }, { unique:true, name:'appointment_unique_idx', partialFilterExpression:{ status:{$in:['booked','completed','no-show']}, paymentStatus:{$in:['deposit_paid','paid']} } });

  await db.createCollection('PAYMENTS', { validator: { $jsonSchema: { bsonType:'object', required:['appointmentId','type','amount','method','status','createdAt'], properties: { appointmentId:{bsonType:'objectId'}, type:{bsonType:'string',enum:['deposit','full']}, amount:{bsonType:'decimal',minimum:0}, currency:{bsonType:'string'}, method:{bsonType:'string',enum:['cash','card','online']}, status:{bsonType:'string',enum:['pending','paid','refunded']}, createdAt:{bsonType:'date'} } } }, validationLevel:'strict' }).catch(()=>{});
  try { await db.collection('PAYMENTS').dropIndex('payment_appointment_unique_idx'); } catch(e) {}
  try { await db.collection('PAYMENTS').dropIndex('appointmentId_1'); } catch(e) {}
  await db.collection('PAYMENTS').createIndex({ appointmentId:1,type:1 }, { unique:true, name:'payment_appointment_type_unique_idx' });

  await db.createCollection('NOTIFICATIONS', { validator: { $jsonSchema: { bsonType:'object', required:['message','target','createdBy','createdAt','read'], properties: { message:{bsonType:'string'}, target:{bsonType:'string',enum:['client','staff','all']}, recipientId:{bsonType:['objectId','null']}, createdBy:{bsonType:'objectId'}, createdAt:{bsonType:'date'}, read:{bsonType:'bool'}, readAt:{bsonType:['date','null']} } } }, validationLevel:'strict' }).catch(()=>{});
  await db.collection('NOTIFICATIONS').createIndex({ createdAt:-1 });

  await db.createCollection('AUDIT_LOG', { validator: { $jsonSchema: { bsonType:'object', required:['collection','documentId','action','performedBy','timestamp'], properties: { collection:{bsonType:'string'}, documentId:{bsonType:'objectId'}, action:{bsonType:'string'}, performedBy:{bsonType:'objectId'}, timestamp:{bsonType:'date'}, data:{bsonType:'object'} } } }, validationLevel:'strict' }).catch(()=>{});

  // REFRESH_TOKENS — persisted so sessions survive server restarts/redeploys
  // (previously an in-memory Set, which lost every session on every deploy).
  // TTL index auto-removes documents once expiresAt passes.
  await db.createCollection('REFRESH_TOKENS').catch(() => {});
  await db.collection('REFRESH_TOKENS').createIndex({ token: 1 }, { unique: true });
  await db.collection('REFRESH_TOKENS').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

  await db.createCollection('GALLERY').catch(()=>{});
  await db.collection('GALLERY').createIndex({ createdAt:-1 });

  // CLIENT GALLERY — before/after photos submitted by clients after appointments
  await db.createCollection('CLIENT_GALLERY', {}).catch(() => {});
  await db.collection('CLIENT_GALLERY').createIndex({ userId: 1 });
  await db.collection('CLIENT_GALLERY').createIndex({ appointmentId: 1 });
  await db.collection('CLIENT_GALLERY').createIndex({ status: 1, createdAt: -1 });

  // CLIENT_NOTIFICATIONS — in-app notifications for customers
  await db.createCollection('CLIENT_NOTIFICATIONS', {}).catch(() => {});
  await db.collection('CLIENT_NOTIFICATIONS').createIndex({ userId: 1, createdAt: -1 });
  await db.collection('CLIENT_NOTIFICATIONS').createIndex({ userId: 1, read: 1 });

  // REFERRALS — referral program
  await db.createCollection('REFERRALS', {}).catch(() => {});
  await db.collection('REFERRALS').createIndex({ referrerId: 1 });
  await db.collection('REFERRALS').createIndex({ referralCode: 1 }, { unique: true });
  await db.collection('REFERRALS').createIndex({ refereeId: 1 });

  // SUBSCRIPTION_PLANS — admin-defined monthly plans
  await db.createCollection('SUBSCRIPTION_PLANS', {}).catch(() => {});
  await db.collection('SUBSCRIPTION_PLANS').createIndex({ isActive: 1 });

  // FEEDBACK — post-visit NPS surveys
  await db.createCollection('FEEDBACK', {}).catch(() => {});
  await db.collection('FEEDBACK').createIndex({ userId: 1 });
  await db.collection('FEEDBACK').createIndex({ appointmentId: 1 }, { unique: true, sparse: true });
  await db.collection('FEEDBACK').createIndex({ createdAt: -1 });
  await db.collection('FEEDBACK').createIndex({ npsScore: 1 });

  // SUBSCRIPTIONS — client subscriptions
  await db.createCollection('SUBSCRIPTIONS', {}).catch(() => {});
  await db.collection('SUBSCRIPTIONS').createIndex({ userId: 1 });
  await db.collection('SUBSCRIPTIONS').createIndex({ planId: 1 });
  await db.collection('SUBSCRIPTIONS').createIndex({ status: 1, renewalDate: 1 });





  // DISCOUNT_CODES
  await db.createCollection('DISCOUNT_CODES', {
    validator: { $jsonSchema: { bsonType:'object', required:['code','type','value','isActive','createdAt'], properties: {
      code:           { bsonType:'string' },
      type:           { bsonType:'string', enum:['percentage','flat'] },
      value:          { bsonType:'number', minimum:0 },
      minOrderAmount: { bsonType:['number','null'] },
      usageLimit:     { bsonType:['int','null'] },
      usedCount:      { bsonType:'int', minimum:0 },
      expiresAt:      { bsonType:['date','null'] },
      isActive:       { bsonType:'bool' },
      description:    { bsonType:'string' },
      createdAt:      { bsonType:'date' },
    }}},
    validationLevel: 'moderate'
  }).catch(()=>{});
  await db.collection('DISCOUNT_CODES').createIndex({ code:1 }, { unique:true });

  // LOYALTY
  await db.createCollection('LOYALTY', {}).catch(() => {});
  await db.collection('LOYALTY').createIndex({ userId: 1 }, { unique: true });

  // LOYALTY_TRANSACTIONS
  await db.createCollection('LOYALTY_TRANSACTIONS', {}).catch(() => {});
  await db.collection('LOYALTY_TRANSACTIONS').createIndex({ userId: 1 });
  await db.collection('LOYALTY_TRANSACTIONS').createIndex({ createdAt: -1 });

  // GIFT_CARDS
  await db.createCollection('GIFT_CARDS', {}).catch(() => {});
  await db.collection('GIFT_CARDS').createIndex({ code: 1 }, { unique: true });
  await db.collection('GIFT_CARDS').createIndex({ recipientEmail: 1 });

  // INVENTORY (purchase orders + stock history)
  await db.createCollection('INVENTORY_ORDERS', {}).catch(() => {});
  await db.collection('INVENTORY_ORDERS').createIndex({ productId: 1 });
  await db.collection('INVENTORY_ORDERS').createIndex({ createdAt: -1 });

  // SUPPLIERS
  await db.createCollection('SUPPLIERS', {}).catch(() => {});
  await db.collection('SUPPLIERS').createIndex({ name: 1 });



  await db.createCollection('PRODUCTS', { validator: { $jsonSchema: { bsonType:'object', required:['name','price','category','stock','isActive','createdAt','updatedAt'], properties: { name:{bsonType:'string',minLength:1}, description:{bsonType:'string'}, price:{bsonType:'decimal',minimum:0}, comparePrice:{bsonType:['decimal','null']}, category:{bsonType:'string',enum:['nails','hair','skincare','accessories','professional','other']}, images:{bsonType:'array',items:{bsonType:'string'}}, stock:{bsonType:'int',minimum:0}, sku:{bsonType:'string'}, brand:{bsonType:'string'}, tags:{bsonType:'array',items:{bsonType:'string'}}, isActive:{bsonType:'bool'}, isFeatured:{bsonType:'bool'}, createdAt:{bsonType:'date'}, updatedAt:{bsonType:'date'} } } }, validationLevel:'moderate' }).catch(()=>{});
  await db.collection('PRODUCTS').createIndex({ name:'text',description:'text',brand:'text',tags:'text' });
  await db.collection('PRODUCTS').createIndex({ category:1 });
  await db.collection('PRODUCTS').createIndex({ isActive:1,isFeatured:-1,createdAt:-1 });

  await db.createCollection('ORDERS', { validator: { $jsonSchema: { bsonType:'object', required:['userId','items','totalAmount','status','paymentStatus','shippingAddress','createdAt','updatedAt'], properties: { userId:{bsonType:'objectId'}, items:{bsonType:'array',minItems:1}, subtotal:{bsonType:'decimal',minimum:0}, shippingFee:{bsonType:'decimal',minimum:0}, totalAmount:{bsonType:'decimal',minimum:0}, status:{bsonType:'string',enum:['pending','confirmed','processing','ready','shipped','delivered','cancelled','refunded']}, paymentStatus:{bsonType:'string',enum:['unpaid','paid','refunded']}, paymentMethod:{bsonType:'string',enum:['yoco','cash','eft']}, yocoCheckoutId:{bsonType:'string'}, shippingAddress:{bsonType:'object'}, trackingNumber:{bsonType:'string'}, notes:{bsonType:'string'}, createdAt:{bsonType:'date'}, updatedAt:{bsonType:'date'} } } }, validationLevel:'moderate' }).catch(()=>{});
  await db.collection('ORDERS').createIndex({ userId:1,createdAt:-1 });
  await db.collection('ORDERS').createIndex({ status:1 });

  await db.createCollection('REVIEWS', { validator: { $jsonSchema: { bsonType:'object', required:['productId','userId','rating','createdAt'], properties: { productId:{bsonType:'objectId'}, userId:{bsonType:'objectId'}, rating:{bsonType:'int',minimum:1,maximum:5}, comment:{bsonType:'string'}, createdAt:{bsonType:'date'} } } }, validationLevel:'moderate' }).catch(()=>{});
  await db.collection('REVIEWS').createIndex({ productId:1,createdAt:-1 });
  await db.collection('REVIEWS').createIndex({ productId:1,userId:1 }, { unique:true });
};

module.exports = initCollections;
