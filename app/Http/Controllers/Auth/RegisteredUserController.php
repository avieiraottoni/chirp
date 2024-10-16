<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules;
use Illuminate\View\View;

class RegisteredUserController extends Controller
{
    /**
     * Exibe a view de registro de novos usuários.
     *
     * @return View - Retorna a view que contém o formulário de registro.
     */
    public function create(): View
    {
        // Renderiza a view 'auth.register' que contém o formulário para criação de uma nova conta.
        return view('auth.register');
    }

    /**
     * Processa uma requisição de registro de um novo usuário.
     *
     * @param Request $request - A requisição HTTP contendo os dados enviados pelo usuário no formulário de registro.
     * @return RedirectResponse - Redireciona o usuário após o registro para a dashboard.
     *
     * @throws \Illuminate\Validation\ValidationException - Lança exceção se houver problemas de validação nos dados.
     */
    public function store(Request $request): RedirectResponse
    {
        // Valida os dados enviados na requisição.
        // 'name': Campo obrigatório, deve ser uma string com no máximo 255 caracteres.
        // 'email': Campo obrigatório, deve ser uma string válida e em minúsculas, com no máximo 255 caracteres,
        // e único na tabela de usuários.
        // 'password': Campo obrigatório, deve ser confirmado (confirmado com password_confirmation) e seguir as regras padrões.
        $request->validate([
            'name' => ['required', 'string', 'max:255'], // O nome deve ser fornecido, ser uma string e ter no máximo 255 caracteres.
            'email' => ['required', 'string', 'lowercase', 'email', 'max:255', 'unique:' . User::class], // E-mail obrigatório, único e em minúsculas.
            'password' => ['required', 'confirmed', Rules\Password::defaults()], // Senha obrigatória, confirmada e seguindo as regras de segurança padrão.
        ]);

        // Cria um novo registro de usuário com os dados validados.
        // O campo 'password' é criptografado com Hash::make() antes de ser salvo.
        $user = User::create([
            'name' => $request->name, // Atribui o nome fornecido.
            'email' => $request->email, // Atribui o e-mail fornecido.
            'password' => Hash::make($request->password), // Criptografa a senha fornecida.
        ]);

        // Dispara o evento Registered para indicar que um novo usuário foi registrado.
        // Isso pode ser usado para executar ações adicionais, como enviar um e-mail de boas-vindas.
        event(new Registered($user));

        // Faz o login automático do novo usuário criado.
        Auth::login($user);

        // Redireciona o usuário para a dashboard após o registro e login bem-sucedidos.
        return redirect(route('dashboard', absolute: false));
    }
}

