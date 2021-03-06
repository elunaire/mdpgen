<html>

<head>
<title>GENERATEUR DE MOTS DE PASSES</title>
<meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.0/jquery.min.js"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
<meta name="description" content="Generer et Memoriser des mots de passes, Generate password, Generacion de contrasena">
	<meta name="keywords" content="generer, regenerer, mot, mots, de, passe, generate, password, generation, automatique, contrasena, automanica, automatique, generation, automatique">
	<meta name="author" content="E. Lunaire">
	


<script src="prng_pmse_base32.js"></script>	
<script src="vendor.js"></script>
<script src="patternlock.js"></script>


 	
	
<SCRIPT LANGUAGE="JavaScript">

// compute Hash function on a 32 bits register
function hash32(tmp){ 
  var hash = 0, i, chr;
  if (tmp.length === 0) return hash;
  for (i = 0; i < tmp.length; i++) {
    chr   = tmp.charCodeAt(i);
    hash  = ((hash << 5) - hash) + chr;
    hash |= 0; // Convert to 32bit integer
  }
  return Math.abs(hash);
}


function MyMdp(){
	
	var mdp1 = document.getElementById("pwd").value;
	var mdp2 = document.getElementById("dateperso").value;	
	mdp1 = hash32(mdp2).toString(32) + mdp1;
	mdp2 = hash32(mdp1).toString(32) + mdp2;
	var tcm = document.getElementById("tailleperso").value;	
	
	//var l_numbers = document.getElementById("myRange").value;
	
	//var pattern = p.getPattern();
	//document.getElementById("areaOut").value = pattern;
	
	var my_pattern = p.getPattern();
	
	var iv = hash32(tcm + mdp2 + mdp1 + my_pattern).toString(16); 
	
	mdp1 = mdp1 + hash32(iv + my_pattern.toString() + tcm).toString(16);
	mdp2 = mdp2 + my_pattern.toString(16) + hash32(iv).toString(32);		
	
	
	
	var l_numbers = document.getElementById("taillemdpliste").value;	
	
	

		
	
	// add index 1, 2, 3... N to column0 of table
	var i, num_txt="";
	for (i = 1; (i-1) < l_numbers; i++) {
		num_txt += i.toString() + "\n";
	}
	document.getElementById("myTDnum").innerText = num_txt;
	
	// add N password to column1 of table
	var res = PRNG_base32(mdp1, mdp2, iv, 8*l_numbers + 1 ) ;
	
	document.getElementById("myTD").innerText = res;

	
  
	
}




function MyPattern(){ 
	var pattern = p.getPattern();
	document.getElementById("val_schema").value = pattern;	
}



</SCRIPT>

</head>


<body>

<div class="container">
  <div class="jumbotron">
    <h1>MOTS DE PASSES</h1>
    <p> (Re)G&eacute;n&eacute;rer une liste de mots de passes robustes que vous pouvez retrouver ! 	</p> 
    <p align="center">  <a href="http://mdpgen.free.fr/en/">EN</a> - <a href="http://mdpgen.free.fr/"> FR</a>   </p> 
  </div>
  <div class="row">
	

   <div class="col-sm-4">
      <h3>Cr&eacute;ation d'une liste de mots de passes (reg&eacute;n&eacute;rable ?? l'identique)</h3>
        <p> Surnom d'un proche (ou mot de passe simple) ? <input type="text"  size="25" maxlength="64" style="text-align:center; color: blue; backgfloor:#FFFFFF; font-size:17;" id="pwd" />
		</p>
		<p> Une Date (ex : anniversaire d'un proche) ? <input type="date" id="dateperso" name="dateperso">
		</p>
		<p> Une taille en cm (ex : votre taille ?? vous) ? <input type="number" id="tailleperso" name="tailleperso">
		</p>
		<p> Une sch&eacute;ma de v&eacute;rrouilage que vous retiendrez ? 
		</p>
		<p>     
           <svg class="patternlock" id="lock" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
            <g class="lock-actives"></g>
            <g class="lock-lines"></g>
            <g class="lock-dots">
                <circle cx="20" cy="20" r="2"/>
                <circle cx="50" cy="20" r="2"/>
                <circle cx="80" cy="20" r="2"/>

                <circle cx="20" cy="50" r="2"/>
                <circle cx="50" cy="50" r="2"/>
                <circle cx="80" cy="50" r="2"/>

                <circle cx="20" cy="80" r="2"/>
                <circle cx="50" cy="80" r="2"/>
                <circle cx="80" cy="80" r="2"/>
            </g>
			<svg>
		</p>
		<p> Sch&eacute;ma : <input type="text"  size="10" maxlength="64" readonly id="val_schema" />
		<input type="button" style="font-size:12; font-family: impact;" value="Voir" onClick="MyPattern()"/>
		</p>
		<p>
		</p>
		
    




    

	</div>
	<div class="col-sm-4">
      <h3>Liste des mots de passes</h3>
	  	<p><input type="button" style="font-size:15; font-family: impact;" value="(Re) Calculer les mots de passes" onClick="MyMdp()"/>
		</p>

		<p>   
		 
		<table id="tableOut"  style="width:100%">
			<tr id="myTr">
				<td vAlign id="myTDnum" >
					
				</td>
				<td vAlign id="myTD"></td>
				
			</tr>
  		</table>		
		</p>
		<p> Nombre de mots de passes (extensible) <input type="number" value="10" id="taillemdpliste" name="taillemdpliste">
		
		</p>

	</div>
	

	
	<div class="col-sm-4">
      <h3>Utilisations</h3>
		<p> 1. Entrer un nom de code (un pseudo, surnom, mot de passe etc.)  <p/>
		<p> 2. Entrer une date que vous connaissez.  <p/>
		<p> 3. Entrer votre taille ou un nombre que vous connaissez.  <p/>
		<p> 4. Entrer un sch&eacute;ma de v&eacute;rrouilage que vous retiendrez.  <p/>
		<p> => Avec ces m??mes champs que vous retiendrez, la liste extensible des mots de passes g&eacute;n&eacute;r&eacute;s sera toujours identique.<p/>
		<p> NB : chaque mot de passe de la liste est utilisable temporairement en retenant son indice... <p/>
	 <h3>Informations</h3>
		<p> Le nombre de combinaisons d'entr&eacute;es possibles de ce calculateur d&eacute;passe largement 10 milliards. 
		Le G&eacute;n&eacute;rateur de mots de passes utilise un g&eacute;n&eacute;rateur particulier de nombre pseudo-al&eacute;atoire (PRNG).
		 Celui-ci admet des entr&eacute;es de tailles non born??es (un espace de graines non born&eacute;). 
		<p> (Plus d'info : <a href="http://blocksnet.free.fr/PRNG/">PULS-PRNG</a>). <p/>
	</div>   
</div>

<script>
    var e = document.getElementById('lock')
    var p = new PatternLock(e, {
        onPattern: function() {
            this.success()
        }
    });

</script>



	


 <footer class="footer">
        <p align="center"> _______________________________________________________ </p>
		<p align="center"> Investissement <a href="https://r.kraken.com/W764n" >Cryptos & Bitcoin ?</a> Il est temps de s'y mettre sur <a href="https://r.kraken.com/W764n" >kraken.com</a> !
		</p>
	  </footer>

</body>


</html>
