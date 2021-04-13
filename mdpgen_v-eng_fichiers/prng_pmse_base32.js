/////////////////////////////////////////////////////////////////////
//      PRNG with unlimited seed space   - Blocksnet    			//
//      This PRNG is used into the PMSE encryption algorithm 		//
//      Author : E.Lunaire			11/2020						   //
//      blocksnet.net               					 		  //
/////////////////////////////////////////////////////////////////////

// Info:
// mdp1 : password1
// mdp2 : password2
// iv : string(6 chars) for vector of initial values (6 values at least)
// size_m : size of the output PRNG vector


/* int 32 version */
function PRNG_base32(mdp1, mdp2, iv, size_m, word_L )    {
	var i=0, j=0, b0_=0, b1_=0, b2_=0, bCst_=0, tmp=0, tmp2=0;
	var prng_srt = "";
	var lm1 = mdp1.length;
	var lm2 = mdp2.length;
	var xt=iv.charCodeAt(0),Yn=iv.charCodeAt(1), x1=iv.charCodeAt(2), x2=iv.charCodeAt(3);
	// Pseudo random chain generation (as long as msg) calculated from password 1 & 2 
	for (i=0; i < (size_m) ; i++){
		
		// Pseudo random byte generation
			
			
		x3  = ((xt^0xF0)>>4) + ((xt^0x0F)<<4);  // xt swapping
          
          b0_ = x3&0x03;
          b1_ = (x3&0x0C)>>2;
          b2_ = (x3&0x30)>>4;
          bCst_ = (x3&0xC0)>>6;

          // variable polynomial of max order = 2 (could be extended)
          Yn = b2_*x2*i*i + b1_*x1*i + Yn>>b0_ + bCst_;
		
          xa = (Yn & 0xFF000000)>>24 ;
          xb = (Yn & 0xFF0000)>>16 ;
          xc = (Yn & 0xFF00)>>8 ;
          xd = Yn & 0xFF;
          x0 = (xa^xb^xc^xd);
		
		x1 =  mdp1.charCodeAt(i%lm1); // simple itterative selection of char of password1
		x2 =  mdp2.charCodeAt((x1+i)%lm2); // char selection from pseudo random key x0
				
		xt = (x0^x1^x2^x3)&0xFF;  // pseudo-random key for xor encryption, depends on x0, x1, x2, x3 
		
        if (xt==0){
			xt=i%iv.charCodeAt(0); Yn = i%iv.charCodeAt(1);
			tmp2 = (tmp2<<8) ;	
		}
		else{
			tmp2 = (tmp2<<8) + xt;			
		}

				
		if ((i%4)==0) {
					tmp = tmp2.toString(32); 
			if(((i%word_L)==0)&& (i > 1)) {
				var	majuscules = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; // 26 chars -->
				tmp = tmp + majuscules.substring((Math.abs(tmp2+i)%26),(Math.abs(tmp2+i)%26)+1) + "\n"; // add CAP+\n
				} // N 32 bits numbers (or passwords in practice) separated by "CAP\n"
			prng_srt = prng_srt + tmp; // add char to string
			tmp2 = 0;
		}
			
		
		
		
	}
	
return prng_srt;


}

