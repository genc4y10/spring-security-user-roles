<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<style type="text/css">
	.failed{ 
	color : red; 
	}
	.succes{ 
	color : green; 
	}

</style>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>CUSTOM LOGIN PAGE</title>
</head>
<body>

	<form:form
		action="${pageContext.request.contextPath}/authenticateTheUser"
		method="POST">

		<c:if test="${param.error != null }">
			<i class="failed">Kullanici adi ve parola giriniz.</i>
		</c:if>
		
		
		<c:if test="${param.logout != null }">
			<i class="succes">CIKIS YAPTINIZ..</i>
		</c:if>

		<p>
			Kullanici adi:<input type="text" name="username" />
		</p>
		<p>
			Sifre<input type="password" name="password" />
		</p>

		<input type="submit" value="GIR" />
		
		<input type="hidden" 
			name="${_csrf.parameterName}"
			value ="${_csrf.token}"
		/> 
	</form:form>

</body>
</html>