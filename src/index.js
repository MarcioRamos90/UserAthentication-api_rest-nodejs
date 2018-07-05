const express = require("express");
const bodyParser = require("body-parser");

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

require("../src/controlles/authcontroler")(app);
require("../src/controlles/projectcontroller")(app);

app.listen(3000);
