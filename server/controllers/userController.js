const User = require("../models/user");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");

//#########################################//
//Creando el token de usuario
//#########################################//

function crearToken(user, SECRET_KEY, expiresIn){
    const { id, name, email, username } = user;
    const payload = {
        id,
        name,
        email,
        username,
    };
    return jwt.sign(payload, SECRET_KEY, { expiresIn });
};

//#########################################//
//Registro de usuario
//#########################################//

async function register(input){
    const newUser = input;
    newUser.email = newUser.email.toLowerCase();
    newUser.username = newUser.username.toLowerCase();

    const {email, username, password} = newUser;

    //revisamos si el email esta en uso
    const foundEmail = await User.findOne({email});
    if(foundEmail) throw new Error("el email ya esta en uso");

    //revisamos si el username esta en uso
    const foundUsername = await User.findOne({username});
    if(foundUsername) throw new Error("el username ya esta en uso");

    //encriptar constraseña
    const salt = await bcryptjs.genSaltSync(10);
    newUser.password = await bcryptjs.hash(password,salt);


    try {
        const user = new User(newUser);
        user.save();
        return user;
    } catch (error) {
        console.log(error);
    }

}
//#########################################//
//Login de usuario
//#########################################//
async function login(input){
    const { email, password } = input;
    
    const userFound = await User.findOne({email: email.toLowerCase()});
    if(!userFound) throw new Error("Error en el email o contraseña");

    const passwordSuccess = await bcryptjs.compare(password, userFound.password);
    if(!passwordSuccess) throw new Error("Error en el email o contraseña");


    return {
        token : crearToken(userFound,process.env.SECRET_KEY,"24h"),
    };
}


//#########################################//
//Obteniendo un usuario
//#########################################//

function getUser(){
    console.log("Obteniendo usuario");
    return null;
}

module.exports = {
    register,
    getUser,
    login,
}