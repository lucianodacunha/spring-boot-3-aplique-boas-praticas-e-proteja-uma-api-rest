# Spring Boot 3: aplique boas práticas e proteja uma API Rest

## 01. Boas práticas na API

- Utilizar a classe ResponseEntity, do Spring, para personalizar os retornos dos métodos de uma classe Controller;

- Modificar o código HTTP devolvido nas respostas da API;

- Adicionar cabeçalhos nas respostas da API;

- Utilizar os códigos HTTP mais apropriados para cada operação realizada na API.


## 02. Lidando com erros

- Criar uma classe para isolar o tratamento de exceptions da API, com a utilização da anotação @RestControllerAdvice;

- Utilizar a anotação @ExceptionHandler, do Spring, para indicar qual exception um determinado método da classe de tratamento de erros deve capturar;

- Tratar erros do tipo 404 (Not Found) na classe de tratamento de erros;

- Tratar erros do tipo 400 (Bad Request), para erros de validação do Bean Validation, na classe de tratamento de erros;

- Simplificar o JSON devolvido pela API em casos de erro de validação do Bean Validation.

### Personalizando mensagens de erro

Você deve ter notado que o Bean Validation possui uma mensagem de erro para cada uma de suas anotações. Por exemplo, quando a validação falha em algum atributo anotado com @NotBlank, a mensagem de erro será: must not be blank.

Essas mensagens de erro não foram definidas na aplicação, pois são mensagens de erro padrão do próprio Bean Validation. Entretanto, caso você queira, pode personalizar tais mensagens.

Uma das maneiras de personalizar as mensagens de erro é adicionar o atributo message nas próprias anotações de validação:


```
public record DadosCadastroMedico(
    @NotBlank(message = "Nome é obrigatório")
    String nome,

    @NotBlank(message = "Email é obrigatório")
    @Email(message = "Formato do email é inválido")
    String email,

    @NotBlank(message = "Telefone é obrigatório")
    String telefone,

    @NotBlank(message = "CRM é obrigatório")
    @Pattern(regexp = "\\d{4,6}", message = "Formato do CRM é inválido")
    String crm,

    @NotNull(message = "Especialidade é obrigatória")
    Especialidade especialidade,

    @NotNull(message = "Dados do endereço são obrigatórios")
    @Valid DadosEndereco endereco) {}
```

Outra maneira é isolar as mensagens em um arquivo de propriedades, que deve possuir o nome ValidationMessages.properties e ser criado no diretório src/main/resources:

```
nome.obrigatorio=Nome é obrigatório
email.obrigatorio=Email é obrigatório
email.invalido=Formato do email é inválido
telefone.obrigatorio=Telefone é obrigatório
crm.obrigatorio=CRM é obrigatório
crm.invalido=Formato do CRM é inválido
especialidade.obrigatoria=Especialidade é obrigatória
endereco.obrigatorio=Dados do endereço são obrigatórios
```

E, nas anotações, indicar a chave das propriedades pelo próprio atributo message, delimitando com os caracteres { e }:

```
public record DadosCadastroMedico(
    @NotBlank(message = "{nome.obrigatorio}")
    String nome,

    @NotBlank(message = "{email.obrigatorio}")
    @Email(message = "{email.invalido}")
    String email,

    @NotBlank(message = "{telefone.obrigatorio}")
    String telefone,

    @NotBlank(message = "{crm.obrigatorio}")
    @Pattern(regexp = "\\d{4,6}", message = "{crm.invalido}")
    String crm,

    @NotNull(message = "{especialidade.obrigatoria}")
    Especialidade especialidade,

    @NotNull(message = "{endereco.obrigatorio}")
    @Valid DadosEndereco endereco) {}
```

## 03. Spring Security

- Funciona o processo de autenticação e autorização em uma API Rest;

- Adicionar o Spring Security ao projeto;

- Funciona o comportamento padrão do Spring Security em uma aplicação;

- Implementar o processo de autenticação na API, de maneira Stateless, utilizando as classes e configurações do Spring Security.

### Mudanças na versão 3.1

A partir da versão 3.1 do Spring Boot algumas mudanças foram realizadas, em relação às configurações de segurança. Caso você esteja utilizando o Spring Boot nessa versão, ou em versões posteriores, o código demonstrado no vídeo anterior vai apresentar um aviso de deprecated, por conta de tais mudanças.

A partir dessa versão, o método securityFilterChain deve ser alterado para:

```
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http.csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .build();
}
```

### Para saber mais:

- [Propriedades do Spring Boot](https://docs.spring.io/spring-boot/docs/current/reference/html/application-properties.html)

- [Tipo de Autenticação](https://www.alura.com.br/artigos/tipos-de-autenticacao?_gl=1*19dekey*_ga*MTc3NTM0NzMwNi4xNjczODg5Nzkz*_ga_1EPWSW3PCS*MTY5Nzc1MDYwNS4xOTIuMS4xNjk3NzU1NDAzLjAuMC4w*_fplc*dDlQVGs2RWExQzRhMnNtV0prd0x0R0g3blpiUEtRbnVnc0VIMUZMeHVGYkElMkZDOTRRVWhuRTdjMWw0SExJUFk4SiUyQlVYY1NORjdtNXk2U2ZBTTVhT0U3bUN1c3lad3U0TSUyQkJsdDRPRzhndlk1OXdHSFN3eTU0b1NpV3FTRnZnJTNEJTNE)

- [Docs Spring Data](https://docs.spring.io/spring-data/jpa/docs/current/reference/html/)


## 04. JSON Web Token

- Adicionar a biblioteca Auth0 java-jwt como dependência do projeto;

- Utilizar essa biblioteca para realizar a geração de um token na API;

- Injetar uma propriedade do arquivo application.properties em uma classe gerenciada pelo Spring, utilizando a anotação @Value;

- Devolver um token gerado na API quando um usuário se autenticar nela.

### Outras informações no token

Além do Issuer, Subject e data de expiração, podemos incluir outras informações no token JWT, de acordo com as necessidades da aplicação. Por exemplo, podemos incluir o id do usuário no token, para isso basta utilizar o método withClaim:

```
return JWT.create()
    .withIssuer("API Voll.med")
    .withSubject(usuario.getLogin())

    .withClaim("id", usuario.getId())

    .withExpiresAt(dataExpiracao())
    .sign(algoritmo);
```

O método withClaim recebe dois parâmetros, sendo o primeiro uma String que identifica o nome do claim (propriedade armazenada no token), e o segundo a informação que se deseja armazenar.

### Para saber mais

- [JWT](https://jwt.io/introduction)
- [O que é JSON Web Tokens?](https://www.alura.com.br/artigos/o-que-e-json-web-tokens?_gl=1*1ur26sd*_ga*MTc3NTM0NzMwNi4xNjczODg5Nzkz*_ga_1EPWSW3PCS*MTY5Nzc4NTczOC4xOTMuMS4xNjk3Nzg3OTE1LjAuMC4w*_fplc*dDlQVGs2RWExQzRhMnNtV0prd0x0R0g3blpiUEtRbnVnc0VIMUZMeHVGYkElMkZDOTRRVWhuRTdjMWw0SExJUFk4SiUyQlVYY1NORjdtNXk2U2ZBTTVhT0U3bUN1c3lad3U0TSUyQkJsdDRPRzhndlk1OXdHSFN3eTU0b1NpV3FTRnZnJTNEJTNE)
- [O que é Json Web Token (JWT)?](https://cursos.alura.com.br/extra/alura-mais/o-que-e-json-web-token-jwt--c203)

## 05. Controle de Acesso

- Funcionam os Filters em uma requisição;

- Implementar um filter criando uma classe que herda da classe OncePerRequestFilter, do Spring;

- Utilizar a biblioteca Auth0 java-jwt para realizar a validação dos tokens recebidos na API;

- Realizar o processo de autenticação da requisição, utilizando a classe SecurityContextHolder, do Spring;

- Liberar e restringir requisições, de acordo com a URL e o verbo do protocolo HTTP.

### Filters

Filter é um dos recursos que fazem parte da especificação de Servlets, a qual padroniza o tratamento de requisições e respostas em aplicações Web no Java. Ou seja, tal recurso não é específico do Spring, podendo assim ser utilizado em qualquer aplicação Java.

É um recurso muito útil para isolar códigos de infraestrutura da aplicação, como, por exemplo, segurança, logs e auditoria, para que tais códigos não sejam duplicados e misturados aos códigos relacionados às regras de negócio da aplicação.

Para criar um Filter, basta criar uma classe e implementar nela a interface Filter (pacote jakarta.servlet). Por exemplo:

```
@WebFilter(urlPatterns = "/api/**")
public class LogFilter implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("Requisição recebida em: " + LocalDateTime.now());
        filterChain.doFilter(servletRequest, servletResponse);
    }

}

```

O método doFilter é chamado pelo servidor automaticamente, sempre que esse filter tiver que ser executado, e a chamada ao método filterChain.doFilter indica que os próximos filters, caso existam outros, podem ser executados. A anotação @WebFilter, adicionada na classe, indica ao servidor em quais requisições esse filter deve ser chamado, baseando-se na URL da requisição.

No curso, utilizaremos outra maneira de implementar um filter, usando recursos do Spring que facilitam sua implementação.

### authorizeRequests deprecated

Na versão 3.0.0 final do Spring Boot uma mudança foi feita no Spring Security, em relação aos códigos que restrigem o controle de acesso.

Ao longo das aulas o método securityFilterChain(HttpSecurity http), declarado na classe SecurityConfigurations, ficou com a seguinte estrutura:

```
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http.csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and().authorizeRequests()
            .antMatchers(HttpMethod.POST, "/login").permitAll()
            .anyRequest().authenticated()
            .and().build();
}
```

Entretanto, desde a versão 3.0.0 final do Spring Boot o método authorizeRequests() se tornou deprecated, devendo ser substituído pelo novo método authorizeHttpRequests(). Da mesma forma, o método antMatchers() deve ser substituído pelo novo método requestMatchers():

```
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http.csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and().authorizeHttpRequests()
            .requestMatchers(HttpMethod.POST, "/login").permitAll()
            .anyRequest().authenticated()
            .and().build();
}
```

### Mudanças na versão 3.1

A partir da versão 3.1 do Spring Boot algumas mudanças foram realizadas, em relação às configurações de segurança. Caso você esteja utilizando o Spring Boot nessa versão, ou em versões posteriores, o código demonstrado no vídeo anterior vai apresentar um aviso de deprecated, por conta de tais mudanças.

A partir dessa versão, o método securityFilterChain deve ser alterado para:

```
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http.csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(req -> {
                req.requestMatchers(HttpMethod.POST, "/login").permitAll();
                req.anyRequest().authenticated();
            })
            .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
}
```

###  Ainda com erro 403?

A utilização do Spring Security para implementar o processo de autenticação e autorização via JWT exige bastante mudanças no código, com a criação de novas classes e alteração de algumas já existentes no projeto. Tais mudanças devem ser feitas com muita atenção, para que o processo de autenticação e autorização na API funcione corretamente.

É bem comum receber erro 403 nas requisições disparadas no Insomnia, mesmo que você tenha implementado todo o código que foi demonstrado ao longo das aulas. Tal erro vai ocorrer somente no caso de você ter cometido algum descuido ao realizar as mudanças no projeto. Entretanto, existem diversas possibilidades que podem causar o erro 403 e veremos a seguir quais podem estar causando tal erro.

1. Erro ao recuperar o token JWT

Na classe SecurityFilter foi criado o método recuperarToken:

```
private String recuperarToken(HttpServletRequest request) {
    var authorizationHeader = request.getHeader("Authorization");
    if (authorizationHeader != null) {
        return authorizationHeader.replace("Bearer ", "");
    }

    return null;
}
```
Na linha do return, dentro do if, utilizamos o método replace da classe String do Java para apagar a palavra Bearer. Repare que existe um espaço em branco após a palavra Bearer. Um erro comum é esquecer de colocar esse espaço em branco e deixar o código assim:

```
return authorizationHeader.replace("Bearer", "");
```
Verifique se você cometeu esse erro no seu código! Uma dica é utilizar também o método trim para apagar os espaços em branco da String:

```
return authorizationHeader.replace("Bearer ", "").trim();
```

2. Issuer diferente ao gerar o token

Na classe TokenService foram criados os métodos gerarToken e getSubject:

```
public String gerarToken(Usuario usuario) {
    try {
        var algoritmo = Algorithm.HMAC256(secret);
        return JWT.create()
                .withIssuer("API Voll.med")
                .withSubject(usuario.getLogin())
                .withExpiresAt(dataExpiracao())
                .sign(algoritmo);
    } catch (JWTCreationException exception){
        throw new RuntimeException("erro ao gerar token jwt", exception);
    }
}

public String getSubject(String tokenJWT) {
    try {
        var algoritmo = Algorithm.HMAC256(secret);
        return JWT.require(algoritmo)
                .withIssuer("API Voll.med")
                .build()
                .verify(tokenJWT)
                .getSubject();
    } catch (JWTVerificationException exception) {
        throw new RuntimeException("Token JWT inválido ou expirado!");
    }
}
```

Repare que nos dois métodos é feita uma chamada ao método withIssuer, da classe ```JWT```:

```
.withIssuer("API Voll.med")
```
Tanto no método gerarToken quanto no getSubject o issuer deve ser exatamente o mesmo. Um erro comum é digitar o issuer diferente em cada método, por exemplo, em um método com letra maiúscula e no outro com letra minúscula.

Verifique se você cometeu esse erro no seu código! Uma dica é converter essa String do issuer em uma constante da classe:

```

private static final String ISSUER = "API Voll.med";

public String gerarToken(Usuario usuario) {
    try {
        var algoritmo = Algorithm.HMAC256(secret);
        return JWT.create()
                .withIssuer(ISSUER)
                .withSubject(usuario.getLogin())
                .withExpiresAt(dataExpiracao())
                .sign(algoritmo);
    } catch (JWTCreationException exception){
        throw new RuntimeException("erro ao gerar token jwt", exception);
    }
}

public String getSubject(String tokenJWT) {
    try {
        var algoritmo = Algorithm.HMAC256(secret);
        return JWT.require(algoritmo)
                .withIssuer(ISSUER)
                .build()
                .verify(tokenJWT)
                .getSubject();
    } catch (JWTVerificationException exception) {
        throw new RuntimeException("Token JWT inválido ou expirado!");
    }
}
```


Também é possível deixar essa String declarada no arquivo application.properties e injetá-la em um atributo na classe, similar ao que foi feito com o atributo secret.

3. Salvar a senha do usuário em texto aberto no banco de dados

Na classe SecurityConfigurations ensinamos ao Spring que nossa API vai utilizar o BCrypt como algoritmo de hashing de senhas:

```
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```


Com isso, ao inserir um usuário na tabela do banco de dados, sua senha deve estar no formato BCrypt e não em texto aberto:

```
mysql> select * from usuarios;
+----+--------------------+--------------------------------------------------------------+
| id | login              | senha                                                        |
+----+--------------------+--------------------------------------------------------------+
|  1 | ana.souza@voll.med | $2a$10$Y50UaMFOxteibQEYLrwuHeehHYfcoafCopUazP12.rqB41bsolF5. |
+----+--------------------+--------------------------------------------------------------+
1 row in set (0,00 sec)
```

Verifique se a senha do usuário que você inseriu na sua tabela de usuários está no formato BCrypt! Um erro comum é inserir a senha em texto aberto. Por exemplo:

```
mysql> select * from usuarios;
+----+--------------------+--------+
| id | login              | senha  |
+----+--------------------+--------+
|  1 | ana.souza@voll.med | 123456 |
+----+--------------------+--------+
1 row in set (0,00 sec)
```

Se esse for o seu caso, execute o seguinte comando sql para atualizar a senha:

```
update usuarios set senha = '$2a$10$Y50UaMFOxteibQEYLrwuHeehHYfcoafCopUazP12.rqB41bsolF5.';
```

Obs: No json enviado pelo Insomnia, na requisição de efetuar login, a senha deve ser enviada em texto aberto mesmo, pois a conversão para BCrypt, e também checagem se ela está correta, é feita pelo próprio Spring.

No caso do erro 403 ainda persistir, alguma exception pode estar sendo lançada mas não sendo capturada pela classe TratadorDeErros que foi criada no projeto. Isso acontece porque o Spring Security intercepta as exceptions referentes ao processo de autenticação/autorização, antes da classe TratadorDeErros ser chamada.

Você pode alterar a classe AutenticacaoController colocando um try catch no método efetuarLogin, para conseguir ver no console qual exception está ocorrendo:

```
@PostMapping
public ResponseEntity efetuarLogin(@RequestBody @Valid DadosAutenticacao dados) {
    try {
        var authenticationToken = new UsernamePasswordAuthenticationToken(dados.login(), dados.senha());
        var authentication = manager.authenticate(authenticationToken);

        var tokenJWT = tokenService.gerarToken((Usuario) authentication.getPrincipal());

        return ResponseEntity.ok(new DadosTokenJWT(tokenJWT));
    } catch (Exception e) {
        e.printStackTrace();
        return ResponseEntity.badRequest().body(e.getMessage());
    }
}
```

Outra dica é também imprimir no console o token que está chegando na API, para você ter a certeza de que ele está chegando corretamente. Para isso, altere o método getSubject, da classe TokenService, modificando a linha que lança a RuntimeException dentro do bloco catch:

```
public String getSubject(String tokenJWT) {
    try {
        var algoritmo = Algorithm.HMAC256(secret);
        return JWT.require(algoritmo)
                .withIssuer(ISSUER)
                .build()
                .verify(tokenJWT)
                .getSubject();
    } catch (JWTVerificationException exception) {
        throw new RuntimeException("Token JWT inválido ou expirado: " +tokenJWT);
    }
}
```

Agora será mais fácil identificar qual exception de fato está ocorrendo na API, causando o erro 403 nas requisições.

### Para saber mais: controle de acesso por url

Na aplicação utilizada no curso não teremos perfis de acessos distintos para os usuários. Entretanto, esse recurso é utilizado em algumas aplicações e podemos indicar ao Spring Security que determinadas URLs somente podem ser acessadas por usuários que possuem um perfil específico.

Por exemplo, suponha que em nossa aplicação tenhamos um perfil de acesso chamado de ADMIN, sendo que somente usuários com esse perfil possam excluir médicos e pacientes. Podemos indicar ao Spring Security tal configuração alterando o método securityFilterChain, na classe SecurityConfigurations, da seguinte maneira:

```
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http.csrf().disable()
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and().authorizeHttpRequests()
        .requestMatchers(HttpMethod.POST, "/login").permitAll()
        .requestMatchers(HttpMethod.DELETE, "/medicos").hasRole("ADMIN")
        .requestMatchers(HttpMethod.DELETE, "/pacientes").hasRole("ADMIN")
        .anyRequest().authenticated()
        .and().addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)
        .build();
}
```

Repare que no código anterior foram adicionadas duas linhas, indicando ao Spring Security que as requisições do tipo DELETE para as URLs /medicos e /pacientes somente podem ser executadas por usuários autenticados e cujo perfil de acesso seja ADMIN.

### Para saber mais: controle de acesso por anotações

Outra maneira de restringir o acesso a determinadas funcionalidades, com base no perfil dos usuários, é com a utilização de um recurso do Spring Security conhecido como Method Security, que funciona com a utilização de anotações em métodos:

```
@GetMapping("/{id}")
@Secured("ROLE_ADMIN")
public ResponseEntity detalhar(@PathVariable Long id) {
    var medico = repository.getReferenceById(id);
    return ResponseEntity.ok(new DadosDetalhamentoMedico(medico));
}
```

No exemplo de código anterior o método foi anotado com @Secured("ROLE_ADMIN"), para que apenas usuários com o perfil ADMIN possam disparar requisições para detalhar um médico. A anotação @Secured pode ser adicionada em métodos individuais ou mesmo na classe, que seria o equivalente a adicioná-la em todos os métodos.

Atenção! Por padrão esse recurso vem desabilitado no spring Security, sendo que para o utilizar devemos adicionar a seguinte anotação na classe Securityconfigurations do projeto:

```
@EnableMethodSecurity(securedEnabled = true)
```

Você pode conhecer mais detalhes sobre o recurso de method security na documentação do Spring Security, disponível em: [https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)

### Para saber mais: Tratando mais erros

No curso não tratamos todos os erros possíveis que podem acontecer na API, mas aqui você encontra uma versão da classe TratadorDeErros abrangendo mais erros comuns:
```
@RestControllerAdvice
public class TratadorDeErros {

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity tratarErro404() {
        return ResponseEntity.notFound().build();
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity tratarErro400(MethodArgumentNotValidException ex) {
        var erros = ex.getFieldErrors();
        return ResponseEntity.badRequest().body(erros.stream().map(DadosErroValidacao::new).toList());
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity tratarErro400(HttpMessageNotReadableException ex) {
        return ResponseEntity.badRequest().body(ex.getMessage());
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity tratarErroBadCredentials() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciais inválidas");
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity tratarErroAuthentication() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Falha na autenticação");
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity tratarErroAcessoNegado() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Acesso negado");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity tratarErro500(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Erro: " +ex.getLocalizedMessage());
    }

    private record DadosErroValidacao(String campo, String mensagem) {
        public DadosErroValidacao(FieldError erro) {
            this(erro.getField(), erro.getDefaultMessage());
        }
    }
}
```