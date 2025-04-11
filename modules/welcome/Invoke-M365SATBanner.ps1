#Fun Banners To Make The Program Awesome!
function Banner
{
  $title = "M365SAT - The Official Microsoft 365 Security Audit Tool"
  $subtitle = "I wish you happy auditting! :)"
  $author = "Leonardo van de Weteringh"
  $version = "Version 3.1 build 11032025"
  $date = "11th of April 2025"
	$banner1 = @"

 __  __ _____  __  ____ ____    _  _____ 
|  \/  |___ / / /_| ___/ ___|  / \|_   _|
| |\/| | |_ \| '_ \___ \___ \ / _ \ | |  
| |  | |___) | (_) |__) |__) / ___ \| |  
|_|  |_|____/ \___/____/____/_/   \_\_|    
                                                       
$($title) - $($version) - $($author) - $($date)
$($subtitle)
"@
	$banner2 = @"

 /00      /00  /000000   /000000  /0000000   /000000   /000000  /00000000
| 000    /000 /00__  00 /00__  00| 00____/  /00__  00 /00__  00|__  00__/
| 0000  /0000|__/  \ 00| 00  \__/| 00      | 00  \__/| 00  \ 00   | 00   
| 00 00/00 00   /00000/| 0000000 | 0000000 |  000000 | 00000000   | 00   
| 00  000| 00  |___  00| 00__  00|_____  00 \____  00| 00__  00   | 00   
| 00\  0 | 00 /00  \ 00| 00  \ 00 /00  \ 00 /00  \ 00| 00  | 00   | 00   
| 00 \/  | 00|  000000/|  000000/|  000000/|  000000/| 00  | 00   | 00   
|__/     |__/ \______/  \______/  \______/  \______/ |__/  |__/   |__/   
                                                                          
$($title) - $($version) - $($author) - $($date)
$($subtitle)            
"@
	
	$banner3 = @"

███╗   ███╗██████╗  ██████╗ ███████╗███████╗ █████╗ ████████╗
████╗ ████║╚════██╗██╔════╝ ██╔════╝██╔════╝██╔══██╗╚══██╔══╝
██╔████╔██║ █████╔╝███████╗ ███████╗███████╗███████║   ██║   
██║╚██╔╝██║ ╚═══██╗██╔═══██╗╚════██║╚════██║██╔══██║   ██║   
██║ ╚═╝ ██║██████╔╝╚██████╔╝███████║███████║██║  ██║   ██║   
╚═╝     ╚═╝╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝    

$($title) - $($version) - $($author) - $($date)
$($subtitle)   
"@
	
	$banner4 = @"

01001101 00110011 00110110 00110101 01010011 01000001 01010100  
                                                                              
$($title) - $($version) - $($author) - $($date)
$($subtitle)
"@
	
	$banner5 = @"                                                 

 _____  _    ____ ____   __  _____ __  __ 
|_   _|/ \  / ___| ___| / /_|___ /|  \/  |
  | | / _ \ \___ |___ \| '_ \ |_ \| |\/| |
  | |/ ___ \ ___) ___) | (_) ___) | |  | |
  |_/_/   \_|____|____/ \___|____/|_|  |_|
                                                  
$($title) - $($version) - $($author) - $($date)
$($subtitle)
"@

$banner6 = @"                                                 

########  #####   #####  #######   ######   ########## #   
       # #     # #     # #                        ###  #   
      #        # #       #       ##########      #     ##  
    ##    #####  ######  ######       #         #      # # 
  ## #         # #     #       #      #        #       #  #
 ##   #  #     # #     # #     #     #        #        #   
#      #  #####   #####   #####    ##        #         #   
                                                 
$($title) - $($version) - $($author) - $($date)
$($subtitle)
"@

$banner7 = @"                                                 

#   # ### ### ###  ####   #   #####
## ##   # #   #   #      # #    #  
# # #  ## ### ### #     #####   #  
#   #   # # #   # #     #   #   #  
#   # ### ### ###  #### #   #   #  
                                                 
$($title) - $($version) - $($author) - $($date)
$($subtitle)
"@

$banner8 = @"                                                 

    /|    //| |     ___       ____     ____    //   ) )  // | |  /__  ___/
   //|   // | |   //   ) )  //       //       ((        //__| |    / /    
  // |  //  | |    __ / /  //__     //__        \\     / ___  |   / /     
 //  | //   | |       ) ) //   ) )      ) )       ) ) //    | |  / /      
//   |//    | | ((___/ / ((___/ / ((___/ / ((___ / / //     | | / /       
                                                 
$($title) - $($version) - $($author) - $($date)
$($subtitle)
"@

#Actual Script::
	$banner = @($banner1, $banner2, $banner3, $banner4, $banner5, $banner6, $banner7, $banner8)
	$bannernumber = (Get-Random -Minimum 1 -Maximum $banner.length)
	$bannercolor = @([Enum]::GetValues([System.ConsoleColor]))
  $bannercolornumber = (Get-Random -Minimum 1 -Maximum $([Enum]::GetValues([System.ConsoleColor]).Length))
  Write-Host ($banner[$bannernumber]) -ForegroundColor ($bannercolor[$bannercolornumber])
}