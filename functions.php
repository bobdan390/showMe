<?php
include_once 'psl-config.php';

function sec_session_start() {
    $session_name = 'sesion_id';   
    $secure = SECURE;   
    $httponly = true;
    if (ini_set('session.use_only_cookies', 1) === FALSE) {
        header("Location: ../error.php?err=Could not initiate a safe session (ini_set)");
        exit();
    }
    $cookieParams = session_get_cookie_params();
    session_set_cookie_params($cookieParams["lifetime"],
        $cookieParams["path"], 
        $cookieParams["domain"], 
        $secure,
        $httponly);
    session_name($session_name);
    session_start();            
    session_regenerate_id();    
}

function login($email, $password, $mysqli) {

    if ($stmt = $mysqli->prepare("SELECT id, username, password, privilege,salt FROM workers WHERE email = ? LIMIT 1")) {
        $stmt->bind_param('s', $email); 
        $stmt->execute();   
        $stmt->store_result();
 
        $stmt->bind_result($user_id, $username, $db_password, $privilege, $salt);
        $stmt->fetch();
 

        $stmt2 = $mysqli->prepare("SELECT name,first_name,schedule,notification,alarm FROM data_workers WHERE id_worker = ? LIMIT 1");
                    $stmt2->bind_param('i', $user_id);  
                    $stmt2->execute();    
                    $stmt2->store_result();
                    $stmt2->bind_result($name,$apellido,$horario,$notificacion,$alarma);
                    $stmt2->fetch();
                    $cake = explode("/", $horario);
                    $hora_inicio = strtotime($cake[0]);
                    $hora_fin = strtotime($cake[1]);
                    $hora_servidor_= strtotime(hora_servidor());

         //echo $hora_inicio . "/" . $hora_fin . "/".$hora_servidor_."/".hora_servidor();           
        if (($hora_inicio <= $hora_servidor_) && ($hora_fin >= $hora_servidor_)) {
                        $_SESSION["aidi"] = $user_id;
                        $_SESSION['name'] = $name;
                        $_SESSION['ape'] = $apellido;
                        $_SESSION['privilegio_'] = $privilege;
                        $_SESSION['alr' ]= $notificacion;
                        $_SESSION["alr_"] = $alarma;

            $password = hash('sha512', $password . $salt);
            if ($stmt->num_rows >= 1) {
                if (checkbrute($user_id, $mysqli) == true) {
                    return false;
                } else {

                    if ($db_password == $password) {

                        $user_browser = $_SERVER['HTTP_USER_AGENT'];
                        $user_id = preg_replace("/[^0-9]+/", "", $user_id);
                        $_SESSION['user_id'] = $user_id;
                        $username = preg_replace("/[^a-zA-Z0-9_\-]+/","",$username);
                        $_SESSION['username'] = $username;
                        $_SESSION['login_string'] = hash('sha512',$password . $user_browser);

                         //VERIFICAMOS LA PRIMERA CONEXION DEL DIA
                            $stmt4 = $mysqli->prepare("SELECT llegada FROM llegadas WHERE id_worker = ? ORDER BY id DESC LIMIT 1");
                            $stmt4->bind_param('i',$user_id);
                            $stmt4->execute();
                            $stmt4->store_result();
                            $stmt4->bind_result($first);
                            $stmt4->fetch();

                            $primeradeldia = false;	
                            $cake_hora = explode(":", $cake[0]);
                            $minutos_llegada = (date("H")-$cake_hora[0])*60 + date("i");
                            if ($stmt4->num_rows == 0) {
                                //SI NO HAY NINGUN REGISTRO INSERTAMOS
                                $time_ = date("Y/m/d H:i:s");
                                $mysqli->query("INSERT INTO llegadas(id_worker,llegada,min) VALUES ('$user_id','$time_','$minutos_llegada')");
                                $primeradeldia = true;
                                
                            }else{
                                //SI HAY REGISTRO EVALUAMOS LA FECHA DEL REGISTRO  
                                $hoy = date("Y/m/d");
                                $cake_llegada = explode(" ", $first);
                                if ($cake_llegada[0] != $hoy) {
                                   $time_ = date("Y/m/d H:i:s");
                                   $mysqli->query("INSERT INTO llegadas(id_worker,llegada,min) VALUES ('$user_id','$time_','$minutos_llegada')");
                                   $primeradeldia = true;

                                }


                                if ($primeradeldia == false) {
                                	$fecha_ = date("Y/m/d");
                                	$h = date("H");
                                	$min_ = date("i:s");
                                	$mysqli->query("INSERT INTO entradas(id_worker,fecha,hora,min) VALUES ('$user_id','$fecha_','$h','$min_')");
                                }


                                
                            }

                        
                        return true;

                    } else {
                        
                        $now = time();
                        /*$mysqli->query("INSERT INTO login_attempts(user_id, time)
                                        VALUES ('$user_id', '$now')");*/
                        return false;
                    }
                }
            } else {
                // El usuario no existe.
                return false;
            }            
        } else {
                return false;
        }
        



    }
}


function checkbrute($user_id, $mysqli) {
    // Obtiene el timestamp del tiempo actual.
    $now = time();
 
    // Todos los intentos de inicio de sesión se cuentan desde las 2 horas anteriores.
    $valid_attempts = $now - (2 * 60 * 60);
 
    if ($stmt = $mysqli->prepare("SELECT time 
                             FROM login_attempts 
                             WHERE user_id = ? 
                            AND time > '$valid_attempts'")) {
        $stmt->bind_param('i', $user_id);
 
        $stmt->execute();
        $stmt->store_result();
 
        // Si ha habido más de 5 intentos de inicio de sesión fallidos.
        if ($stmt->num_rows > 5) {
            return true;
        } else {
            return false;
        }
    }
}

function login_check($mysqli) {
    // Revisa si todas las variables de sesión están configuradas.
    if (isset($_SESSION['user_id'],$_SESSION['username'],$_SESSION['login_string'])) {
 
        $user_id = $_SESSION['user_id'];
        $login_string = $_SESSION['login_string'];
        $username = $_SESSION['username'];

        $user_browser = $_SERVER['HTTP_USER_AGENT'];
 
        if ($stmt = $mysqli->prepare("SELECT password FROM workers WHERE id = ? LIMIT 1")) {

            $stmt->bind_param('i', $user_id);
            $stmt->execute();   
            $stmt->store_result();
 
            if ($stmt->num_rows == 1) {
                
                $stmt->bind_result($password);
                $stmt->fetch();
                $login_check = hash('sha512', $password . $user_browser);
 
                if ($login_check == $login_string) {
                    // ¡¡Conectado!! 
                    return true;
                } else {
                    // No conectado.
                    return false;
                }
            } else {
                // No conectado.
                return false;
            }
        } else {
            // No conectado.
            return false;
        }
    } else {
        // No conectado.
        return false;
    }
}


function esc_url($url) {
 
    if ('' == $url) {
        return $url;
    }
 
    $url = preg_replace('|[^a-z0-9-~+_.?#=!&;,/:%@$\|*\'()\\x80-\\xff]|i', '', $url);
 
    $strip = array('%0d', '%0a', '%0D', '%0A');
    $url = (string) $url;
 
    $count = 1;
    while ($count) {
        $url = str_replace($strip, '', $url, $count);
    }
 
    $url = str_replace(';//', '://', $url);
 
    $url = htmlentities($url);
 
    $url = str_replace('&amp;', '&#038;', $url);
    $url = str_replace("'", '&#039;', $url);
 
    if ($url[0] !== '/') {
        return '';
    } else {
        return $url;
    }
}

function hora_servidor(){

    return date('H:i');
}

function hora_servidor_15($item){
              $segundos_horaInicial=strtotime(hora_servidor());
              $segundos_minutoAnadir=$item*60;
              $nuevaHora=date("H:i",$segundos_horaInicial+$segundos_minutoAnadir);
              return $nuevaHora;
}



function getRealIP() {
if (!empty($_SERVER["HTTP_CLIENT_IP"]))
return $_SERVER["HTTP_CLIENT_IP"];

if (!empty($_SERVER["HTTP_X_FORWARDED_FOR"]))
return $_SERVER["HTTP_X_FORWARDED_FOR"];

return $_SERVER["REMOTE_ADDR"];
}


function minutos_entre_fechas($diadelmes,$hora,$time_response){
    $fecha1 = date("Y")."-".date("m")."-".$diadelmes." ".$hora.":00";
    $fecha2 = str_replace('/', '-', $time_response);
    $minutos = ceil((strtotime($fecha2) - strtotime($fecha1)) / 60);

    return $minutos;
}
?>