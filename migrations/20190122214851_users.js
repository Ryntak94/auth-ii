
exports.up = function(knex, Promise) {
  return knex.schema.createTable('users',   table   =>  {
      table.increments();
      table.string('username').notNullable();
      table.unique('username');
      table.string('password');
      table.string('department');
  })
};

exports.down = function(knex, Promise) {
    return knex.schema.dropTableIfExists('users');
};
