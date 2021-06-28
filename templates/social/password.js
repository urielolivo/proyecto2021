function Generar()
{
    var Caracteres = "0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM!@#="
    var tam=10;
    var pass= "";
   
    for(var i=0; i<tam; i++)
    {
        var rand= Math.floor(Math.random()*Caracteres.length);
        pass += Caracteres.substring(rand, rand +1);
     }
     document.getElementById("id_contrasena").value = pass;
}

