#Fun Banners To Make The Program Awesome!
function Banner
{
  $title = "M365SAT - The Official Microsoft 365 Security Audit Tool"
  $subtitle = "I wish you happy auditting! :)"
  $author = "Leonardo van de Weteringh"
  $version = "Version 2.1.1"
	$banner1 = @"

______  _______________________________________________
___   |/  /_|__  /_  ___/__  ____/_  ___/__    |__  __/
__  /|_/ /___/_ <_  __ \______ \ _____ \__  /| |_  /   
_  /  / / ____/ // /_/ / ____/ / ____/ /_  ___ |  /    
/_/  /_/  /____/ \____/ /_____/  /____/ /_/  |_/_/     
                                                       
$($title) - $($version) - $($author)
$($subtitle)
"@
	$banner2 = @"

    e   e     ,8,"88b,   e88",8,  8888888  dP"8     e Y8b     88P'888'Y88 
   d8b d8b     " ,88P'  d888  "   88      C8b Y    d8b Y8b    P'  888  'Y 
  e Y8b Y8b      C8K   C8888 88e  """Y88b  Y8b    d888b Y8b       888     
 d8b Y8b Y8b   e `88b,  Y888 888D  e  888 b Y8D  d888888888b      888     
d888b Y8b Y8b "8",88P'   "88 88"  "8",88P 8edP  d8888888b Y8b     888     
                                                                          
$($title) - $($version) - $($author)
$($subtitle)            
"@
	
	$banner3 = @"

    ...     ..      ..                                                          ...              ..                  .....          
  x*8888x.:*8888: -"888:     .x~~"*Weu.       .ue~~%u.     cuuu....uK       .x888888hx    :   :**888H: `: .xH""   .H8888888h.  ~-.  
 X   48888X `8888H  8888    d8Nu.  9888c    .d88   z88i    888888888       d88888888888hxx   X   `8888k XX888     888888888888x  `> 
X8x.  8888X  8888X  !888>   88888  98888   x888E  *8888    8*888**"       8" ... `"*8888%`  '8hx  48888 ?8888    X~     `?888888hx~ 
X8888 X8888  88888   "*8%-  "***"  9888%  :8888E   ^""     >  .....      !  "   ` .xnxx.    '8888 '8888 `8888    '      x8.^"*88*"  
'*888!X8888> X8888  xH8>         ..@8*"   98888E.=tWc.     Lz"  ^888Nu   X X   .H8888888%:   %888>'8888  8888     `-:- X8888x       
  `?8 `8888  X888X X888>      ````"8Weu   98888N  '888N    F     '8888k  X 'hn8888888*"   >    "8 '888"  8888          488888>      
  -^  '888"  X888  8888>     ..    ?8888L 98888E   8888E   ..     88888> X: `*88888%`     !   .-` X*"    8888        .. `"88*       
   dx '88~x. !88~  8888>   :@88N   '8888N '8888E   8888E  @888L   88888  '8h.. ``     ..x8>     .xhx.    8888      x88888nX"      . 
 .8888Xf.888x:!    X888X.: *8888~  '8888F  ?888E   8888" '8888F   8888F   `88888888888888f    .H88888h.~`8888.>   !"*8888888n..  :  
:""888":~"888"     `888*"  '*8"`   9888%    "88&   888"   %8F"   d888"     '%8888888888*"    .~  `%88!` '888*~   '    "*88888888*   
    "~'    "~        ""      `~===*%"`        ""==*""      ^"===*%"`          ^"****""`            `"     ""             ^"***"'     

$($title) - $($version) - $($author)
$($subtitle)   
"@
	
	$banner4 = @"

oooo     oooo  ooooooo     ooooooo   oooooooooo oooooooo8      o   ooooooooooo 
 8888o   888 o88    888o o88         888       888            888  88  888  88 
 88 888o8 88     88888o  888888888o  888888888o 888oooooo    8  88     888     
 88  888  88 88o    o888 88o    o888 ooo    o888       888  8oooo88    888     
o88o  8  o88o  88ooo88     88ooo88     88ooo88 o88oooo888 o88o  o888o o888o    
                                                                              
$($title) - $($version) - $($author)
$($subtitle)
"@
	
	$banner5 = @"                                                 

    `Yb              `Yb                      db               
    `8               `8                  db    db            
     8                8                                      
`Yb d88b d88b   'Y888888888888b.    88888888888b.    8888888b. .d888b.    'Yb    `Yb.d888b  
88P   88   8b   .P' .P' .P'        8 .P' .P'        8 .P'     8'   `Yb    88     88'    8Y 
88    8P   88   8   8   8    b    .P 8   8    b    .P 8    b  Yb.   88    88     88     8P 
88  .dP  .dP    `Ybd`Ybd`YbwP'   .P' `Ybd`YbwP'   .P' `YbwP'      .dP    .8P     88   ,dP  
.888888888888b.                   8    b           8    b        .dP'             88        
   `YbwP'           `YbwP'      .dP'               88        
                                                  .8P        
                                                  
$($title) - $($version) - $($author)
$($subtitle)
"@

#Actual Script::
	$banner = @($banner1, $banner2, $banner3, $banner4, $banner5)
	$bannernumber = (Get-Random -Maximum $banner.length)
	$bannercolor = @("Red","DarkYellow","Yellow","Green","Blue","Magenta")
  $bannercolornumber = (Get-Random -Maximum $bannercolor.length)
  Write-Host ($banner[$bannernumber]) -ForegroundColor ($bannercolor[$bannercolornumber])
}