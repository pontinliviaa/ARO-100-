
from flask import Flask, render_template, request, flash, redirect, url_for, session

import fdb

from flask_bcrypt import Bcrypt

# CONFIGURAÇÃO DO FLASK
app = Flask(__name__, template_folder="Templates", static_folder="Static", static_url_path="/static")
bcrypt = Bcrypt(app)
app.config["SECRET_KEY"] = "Chavesdfglkjhgfdshjkjhgfdcvbmnb"
# CONEXÃO COM O BANCO
host = "localhost"
database = r"C:\Users\Aluno\Downloads\ARO-100--main\ARO-100--main\Projeto-Aro-15-10-main\BANCO-ARO-CREDITO-FINAL\BANCO.FDB"
user = "SYSDBA"
password = "sysdba"

con = fdb.connect(
    host=host,
    database=database,
    user=user,
    password=password
)

# VERIFICAÇÃO DE SENHA FORTE

def senha_forte(senha):
    if len(senha) < 8 :
        return False

    tem_maiuscula = False
    tem_minuscula = False
    tem_numero = False
    tem_simbolo = False

    # Verifica cada caractere da senha.
    for caractere in senha:
        if caractere.isupper():
            tem_maiuscula = True
        if caractere.islower():
            tem_minuscula = True
        if caractere.isdigit():
            tem_numero = True
        if caractere in "!@#%":
            tem_simbolo = True
        if caractere.isspace():
            return False

    if tem_maiuscula and tem_minuscula and tem_numero and tem_simbolo:
        return True
    else:
        return False


# VERIFICA A SENHA CRIPTOGRAFADA

def verificar_senha(senha_hash, senha):
    return bcrypt.check_password_hash(senha_hash, senha)

# VERIFICA SE O USUÁRIO ESTÁ AUTENTICADO

def usuario_autenticado():
    if "id_usuario" not in session:
        return False

    cursor = con.cursor()
    try:
        # Consulta somente a conta que está na sessão.
        cursor.execute("""SELECT ATIVO, BLOQUEADO_LOGIN FROM USUARIO
                          WHERE ID_USUARIO = ?""", (session["id_usuario"],))
        usuario = cursor.fetchone()
        con.commit()

        if usuario:
            if usuario[0] == 1 and usuario[1] == 0:
                return True

        return False
    except Exception:
        con.rollback()
        return False
    finally:
        con.rollback()
        cursor.close()

# PÁGINA INICIAL DO SITE

@app.route("/")
def landing():
    return render_template("landing.html")

# PÁGINA DO USUÁRIO LOGADO

@app.route("/novo")
def novo():
    if not usuario_autenticado():
        session.clear()

        flash("Precisa estar logado e ativo!", "error")

        return redirect(url_for("login"))

    if "nome_usuario" not in session:
        session.clear()

        flash("Faça login novamente!", "error")

        return redirect(url_for("login"))

    return render_template("inicio.html", usuario=session["nome_usuario"])

# PÁGINA DE CADASTRO

@app.route("/cadastro")
def pagina_cadastro():
    return render_template("cadastro.html")

# CADASTRAR USUÁRIO

@app.route("/cadastro", methods=["POST"])
def cadastro():
    nome = request.form.get("nome", "").strip()

    email = request.form.get("email", "").strip()

    senha = request.form.get("senha", "")

    confirmar_senha = request.form.get("confirmar_senha", "")

    receita_mensal = request.form.get("renda_mensal", "").strip()

    despesa_mensal = request.form.get("despesas_mensal", "").strip()

    tipo_usuario = 7

    if not nome or not email or not senha or not confirmar_senha or not receita_mensal or not despesa_mensal:
        flash("Preencha todos os campos!", "error")

        return redirect(url_for("pagina_cadastro"))

    if senha != confirmar_senha:
        flash("A senha e a confirmação de senha não são iguais!", "error")

        return redirect(url_for("pagina_cadastro"))

    if not senha_forte(senha):
        flash(
            "A senha deve ter pelo menos 8 caracteres, letras maiúsculas, minúsculas, números e um símbolo (! @ # %) e sem espaços. ",
            "error"
        )

        return redirect(url_for("pagina_cadastro"))

    cursor = con.cursor()

    try:
        # VERIFICA E-MAIL REPETIDO

        cursor.execute("""SELECT ID_USUARIO FROM USUARIO WHERE UPPER(EMAIL) = UPPER(?)""", (email,))

        if cursor.fetchone():
            flash("Este e-mail já está cadastrado!", "error")

            return redirect(url_for("pagina_cadastro"))

        # CONVERTE RENDA E DESPESAS

        receita_mensal = float(receita_mensal)

        despesa_mensal = float(despesa_mensal)

        # Impede renda ou despesas negativas.

        if receita_mensal < 0 or despesa_mensal < 0:
            flash("Os valores não podem ser negativos!", "error")

            return redirect(url_for("pagina_cadastro"))

        # CRIPTOGRAFA A SENHA

        senha_hash = bcrypt.generate_password_hash(senha).decode("utf-8")

        # SALVA O USUÁRIO NO BANCO

        cursor.execute("""INSERT INTO USUARIO (NOME, EMAIL, SENHA, RECEITA_MENSAL, DESPESA_MENSAL, TIPO_USUARIO) VALUES (?, ?, ?, ?, ?, ?)""", (
            nome,
            email,
            senha_hash,
            receita_mensal,
            despesa_mensal,
            tipo_usuario
        ))

        con.commit()

        flash("Cadastro realizado com sucesso!", "success")

        return redirect(url_for("login"))

    except ValueError:
        con.rollback()

        flash("Digite valores válidos para renda e despesas.", "error")

        return redirect(url_for("pagina_cadastro"))

    except Exception as e:
        con.rollback()

        flash(f"Erro ao cadastrar: {e}", "error")

        return redirect(url_for("pagina_cadastro"))

    finally:
        con.rollback()
        cursor.close()

# PÁGINA DE LOGIN

@app.route("/login")
def login():
    return render_template("login.html")

# ENTRAR NA CONTA

@app.route("/login", methods=["POST"])
def entrar_usuario():
    email = request.form.get("email", "").strip()

    senha = request.form.get("senha", "")

    if not email or not senha:
        flash("Preencha o e-mail e a senha!", "error")
        return redirect(url_for("login"))

    cursor = con.cursor()
    try:
        # Busca os dados e as tentativas da conta informada.
        cursor.execute("""SELECT ID_USUARIO, NOME, SENHA, ATIVO,
                          TENTATIVAS_LOGIN, BLOQUEADO_LOGIN
                          FROM USUARIO WHERE UPPER(EMAIL) = UPPER(?)""", (email,))
        usuario = cursor.fetchone()

        if not usuario:
            flash("E-mail ou senha incorretos!", "error")
            return redirect(url_for("login"))

        id_usuario, nome, senha_hash, ativo, tentativas, bloqueado = usuario

        if ativo != 1:
            flash("Usuário inativo!", "error")
            return redirect(url_for("login"))

        if bloqueado == 1 or tentativas >= 3:
            flash("Usuário bloqueado! Solicite o desbloqueio.", "error")
            return redirect(url_for("login"))

        # Se acertar a senha, zera apenas as tentativas desta conta.
        if verificar_senha(senha_hash, senha):
            cursor.execute("""UPDATE USUARIO SET TENTATIVAS_LOGIN = 0
                              WHERE ID_USUARIO = ?""", (id_usuario,))
            con.commit()

            session.clear()
            session["id_usuario"] = id_usuario
            session["nome_usuario"] = nome
            flash("Login realizado com sucesso!", "success")
            return redirect(url_for("novo"))

        # Se errar a senha, soma uma tentativa.
        tentativas = tentativas + 1

        if tentativas >= 3:
            bloqueado = 1
            flash("Usuário bloqueado após 3 tentativas!", "error")
        else:
            flash(f"Senha incorreta! Restam {3 - tentativas} tentativa(s).", "error")

        # O ID no WHERE garante que somente esta conta será alterada.
        cursor.execute("""UPDATE USUARIO
                          SET TENTATIVAS_LOGIN = ?, BLOQUEADO_LOGIN = ?
                          WHERE ID_USUARIO = ?""", (tentativas, bloqueado, id_usuario))
        con.commit()
        return redirect(url_for("login"))

    except Exception:
        con.rollback()
        flash("Não foi possível entrar. Verifique a conexão com o banco.", "error")
        return redirect(url_for("login"))
    finally:
        # Encerra a consulta, inclusive quando o login é recusado.
        con.rollback()
        cursor.close()

# LOGOUT

@app.route("/logout", methods=["POST"])
def logout():
    if "id_usuario" not in session:
        flash("Precisa estar logado!", "error")

        return redirect(url_for("login"))

    session.clear()

    flash("Você saiu da sua conta!", "success")

    return redirect(url_for("login"))

# EDITAR USUÁRIO

@app.route("/editar_usuario")
def editar_usuario():
    if not usuario_autenticado():
        session.clear()

        flash("Precisa estar logado e ativo!", "error")

        return redirect(url_for("login"))

    cursor = con.cursor()
    try:
        cursor.execute("""SELECT ID_USUARIO, NOME, EMAIL, RECEITA_MENSAL, DESPESA_MENSAL, TIPO_USUARIO FROM USUARIO WHERE ID_USUARIO = ?""", (session["id_usuario"],))

        usuario = cursor.fetchone()

        if not usuario:
            session.clear()

            flash("Usuário não encontrado!", "error")

            return redirect(url_for("login"))

        return render_template("editar_usuario.html", usuario=usuario)
    finally:
        con.rollback()
        cursor.close()

# SALVAR EDIÇÃO DO USUÁRIO

@app.route("/salvar_edicao", methods=["POST"])
def salvar_edicao():
    if not usuario_autenticado():
        session.clear()

        flash("Precisa estar logado e ativo!", "error")

        return redirect(url_for("login"))

    nome = request.form.get("nome", "").strip()

    email = request.form.get("email", "").strip()

    senha = request.form.get("senha", "")

    confirmar_senha = request.form.get("confirmar_senha", "")

    receita_mensal = request.form.get("renda_mensal", "").strip()

    despesa_mensal = request.form.get("despesas_mensal", "").strip()

    if not nome or not email or not receita_mensal or not despesa_mensal:
        flash("Preencha todos os campos!", "error")

        return redirect(url_for("editar_usuario"))

    if senha != confirmar_senha:
        flash("A nova senha e a confirmação não são iguais!", "error")

        return redirect(url_for("editar_usuario"))

    if senha and not senha_forte(senha):
        flash(
            "A nova senha deve ter pelo menos 8 caracteres, letras maiúsculas, minúsculas, números e um símbolo (! @ # %), sem espaços e com até 72 bytes em UTF-8.",
            "error")

        return redirect(url_for("editar_usuario"))

    cursor = con.cursor()
    try:
        # VERIFICA E-MAIL REPETIDO

        cursor.execute("""SELECT ID_USUARIO FROM USUARIO WHERE UPPER(EMAIL) = UPPER(?) AND ID_USUARIO <> ?""", (email, session["id_usuario"]))

        if cursor.fetchone():
            flash("Este e-mail já está cadastrado!", "error")

            return redirect(url_for("editar_usuario"))

        # CONVERTE RENDA E DESPESAS

        receita_mensal = float(receita_mensal)

        despesa_mensal = float(despesa_mensal)



        if receita_mensal < 0 or despesa_mensal < 0:
            flash("Os valores não podem ser negativos!", "error")

            return redirect(url_for("editar_usuario"))

        # ATUALIZA OS DADOS

        if senha:
            cursor.execute("""SELECT SENHA, SENHA_ANTERIOR1, SENHA_ANTERIOR2, SENHA_ANTERIOR3 FROM USUARIO WHERE ID_USUARIO = ?""", (session["id_usuario"],))

            dados = cursor.fetchone()

            if not dados:
                session.clear()

                flash("Usuário não encontrado!", "error")

                return redirect(url_for("login"))

            # VERIFICA AS SENHAS ANTERIORES

            for senha_antiga in dados:
                if senha_antiga:
                    if verificar_senha(senha_antiga, senha):
                        flash(
                            "Você não pode reutilizar a senha atual nem as 3 anteriores!",
                            "error"
                        )

                        return redirect(url_for("editar_usuario"))

            # CRIPTOGRAFA A NOVA SENHA

            senha_hash = bcrypt.generate_password_hash(senha).decode("utf-8")

            # ATUALIZA OS DADOS E O HISTÓRICO

            cursor.execute("""UPDATE USUARIO SET NOME = ?, EMAIL = ?, SENHA_ANTERIOR3 = SENHA_ANTERIOR2, SENHA_ANTERIOR2 = SENHA_ANTERIOR1, SENHA_ANTERIOR1 = SENHA, SENHA = ?, RECEITA_MENSAL = ?, DESPESA_MENSAL = ? WHERE ID_USUARIO = ?""", (
                nome,
                email,
                senha_hash,
                receita_mensal,
                despesa_mensal,
                session["id_usuario"]
            ))

        else:
            cursor.execute("""UPDATE USUARIO SET NOME = ?, EMAIL = ?, RECEITA_MENSAL = ?, DESPESA_MENSAL = ? WHERE ID_USUARIO = ?""", (
                nome,
                email,
                receita_mensal,
                despesa_mensal,
                session["id_usuario"]
            ))

        # SALVA NO BANCO

        con.commit()

        session["nome_usuario"] = nome

        flash("Usuário atualizado com sucesso!", "success")

        return redirect(url_for("novo"))

    except ValueError:
        con.rollback()

        flash("Digite valores numéricos válidos!", "error")

        return redirect(url_for("editar_usuario"))

    except Exception as e:
        con.rollback()

        flash(f"Erro ao editar usuário: {e}", "error")

        return redirect(url_for("editar_usuario"))
    finally:
        con.rollback()
        cursor.close()

# SALDO ATUAL

@app.route("/saldo_atual")
def saldo_atual():
    if not usuario_autenticado():
        session.clear()
        flash("Faça login para acessar esta página!", "error")
        return redirect(url_for("login"))

    return render_template("saldo_atual.html")

# INICIA O SERVIDOR

if __name__ == "__main__":
    # Atende uma requisição por vez porque o projeto usa uma conexão global.
    app.run(debug=True, threaded=False)
