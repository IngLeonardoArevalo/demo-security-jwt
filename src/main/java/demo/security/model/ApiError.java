package demo.security.model;

import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonFormat.Shape;

public class ApiError {
	private HttpStatus estado;
	@JsonFormat(shape = Shape.STRING, pattern = "dd/MM/yyyy HH:mm:ss")
	private LocalDateTime fecha = LocalDateTime.now();
	private String mensaje;
	public HttpStatus getEstado() {
		return estado;
	}
	public void setEstado(HttpStatus estado) {
		this.estado = estado;
	}
	public LocalDateTime getFecha() {
		return fecha;
	}
	public void setFecha(LocalDateTime fecha) {
		this.fecha = fecha;
	}
	public String getMensaje() {
		return mensaje;
	}
	public void setMensaje(String mensaje) {
		this.mensaje = mensaje;
	}
	public ApiError(HttpStatus estado, String mensaje) {
		this.estado = estado;
		this.mensaje = mensaje;
	}
	public ApiError() {

	}
	
	
	
	
}
